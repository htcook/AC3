import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import {
  Card, CardContent, CardDescription, CardHeader, CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger,
} from "@/components/ui/dialog";
import {
  Target, Shield, Zap, Activity, Plus, Save, RotateCcw,
  AlertTriangle, TrendingUp, BarChart3, Crosshair, Flame,
  Gauge, RefreshCw, Eye, Trash2, Copy, Brain, Server,
  Building2, Layers, Cpu, Network, FileSearch, Clock,
  ArrowRight, ChevronDown, ChevronUp, Info, Lock, Globe,
  Wifi, Database, Monitor, Smartphone, HardDrive, Download,
} from "lucide-react";
import { exportScoringTimeline } from "@/lib/export-utils";
import {
  Tooltip, TooltipContent, TooltipProvider, TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  Accordion, AccordionContent, AccordionItem, AccordionTrigger,
} from "@/components/ui/accordion";
import AppShell from "@/components/AppShell";

// ─── Risk band colors ──────────────────────────────────────────────────
const RISK_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
};

const RISK_BG: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-green-500/20 text-green-400 border-green-500/30",
};

const IMPACT_COLORS: Record<string, string> = {
  catastrophic: "#dc2626",
  severe: "#ea580c",
  significant: "#d97706",
  moderate: "#65a30d",
  minimal: "#16a34a",
};

// ─── Weight Slider Component ───────────────────────────────────────────
function WeightSlider({
  label, value, onChange, description, color = "cyan",
}: {
  label: string; value: number; onChange: (v: number) => void;
  description: string; color?: string;
}) {
  const pct = (value / 10) * 100;
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between">
        <Label className="text-xs text-zinc-400">{label}</Label>
        <span className="text-xs font-mono text-zinc-300">{value.toFixed(1)}</span>
      </div>
      <div className="relative h-2 bg-zinc-800 rounded-full overflow-hidden">
        <div
          className="absolute inset-y-0 left-0 rounded-full transition-all"
          style={{
            width: `${pct}%`,
            backgroundColor: color === "cyan" ? "#06b6d4" : color === "amber" ? "#f59e0b" : "#8b5cf6",
          }}
        />
      </div>
      <input
        type="range" min="0" max="10" step="0.5" value={value}
        onChange={(e) => onChange(parseFloat(e.target.value))}
        className="w-full h-2 opacity-0 cursor-pointer absolute -mt-3"
        style={{ position: "relative" }}
      />
      <p className="text-[10px] text-zinc-500">{description}</p>
    </div>
  );
}

// ─── Meta Weight Slider ────────────────────────────────────────────────
function MetaSlider({
  label, value, onChange, color,
}: {
  label: string; value: number; onChange: (v: number) => void; color: string;
}) {
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between">
        <Label className="text-xs text-zinc-400">{label}</Label>
        <span className="text-xs font-mono text-zinc-300">{(value * 100).toFixed(0)}%</span>
      </div>
      <div className="relative h-3 bg-zinc-800 rounded-full overflow-hidden">
        <div
          className="absolute inset-y-0 left-0 rounded-full transition-all"
          style={{ width: `${value * 100}%`, backgroundColor: color }}
        />
      </div>
      <input
        type="range" min="0" max="1" step="0.05" value={value}
        onChange={(e) => onChange(parseFloat(e.target.value))}
        className="w-full h-3 opacity-0 cursor-pointer"
        style={{ position: "relative", marginTop: "-12px" }}
      />
    </div>
  );
}

// ─── Radar Chart (SVG) ─────────────────────────────────────────────────
function RadarChart({
  factors,
}: {
  factors: { factor: string; category: string; rawScore: number; weight: number; weightedScore: number }[];
}) {
  const cx = 150, cy = 150, r = 120;
  const n = factors.length;
  if (n === 0) return null;

  const angleStep = (2 * Math.PI) / n;
  const points = factors.map((f, i) => {
    const angle = -Math.PI / 2 + i * angleStep;
    const val = Math.min(f.rawScore / 10, 1);
    return {
      x: cx + r * val * Math.cos(angle),
      y: cy + r * val * Math.sin(angle),
      lx: cx + (r + 20) * Math.cos(angle),
      ly: cy + (r + 20) * Math.sin(angle),
      label: f.factor,
      category: f.category,
      raw: f.rawScore,
    };
  });

  const gridLevels = [0.25, 0.5, 0.75, 1.0];

  return (
    <svg viewBox="0 0 300 300" className="w-full max-w-[300px] mx-auto">
      {gridLevels.map((level) => (
        <polygon
          key={level}
          points={Array.from({ length: n }, (_, i) => {
            const angle = -Math.PI / 2 + i * angleStep;
            return `${cx + r * level * Math.cos(angle)},${cy + r * level * Math.sin(angle)}`;
          }).join(" ")}
          fill="none" stroke="#374151" strokeWidth="0.5"
        />
      ))}
      {points.map((p, i) => (
        <line key={i} x1={cx} y1={cy} x2={cx + r * Math.cos(-Math.PI / 2 + i * angleStep)} y2={cy + r * Math.sin(-Math.PI / 2 + i * angleStep)} stroke="#4b5563" strokeWidth="0.5" />
      ))}
      <polygon
        points={points.map((p) => `${p.x},${p.y}`).join(" ")}
        fill="rgba(6, 182, 212, 0.2)" stroke="#06b6d4" strokeWidth="2"
      />
      {points.map((p, i) => (
        <circle key={i} cx={p.x} cy={p.y} r="4"
          fill={p.category === "CARVER" ? "#06b6d4" : "#f59e0b"} stroke="#1f2937" strokeWidth="1"
        />
      ))}
      {points.map((p, i) => (
        <text key={i} x={p.lx} y={p.ly} textAnchor="middle" dominantBaseline="middle"
          className="text-[8px] fill-zinc-400"
        >
          {p.label.slice(0, 6)}
        </text>
      ))}
    </svg>
  );
}

// ─── Enhanced Heat Map Grid ───────────────────────────────────────────
function HeatMapGrid({
  assets,
}: {
  assets: {
    id: number; hostname: string | null; assetType: string | null;
    hybridRiskScore: number | null; riskBand: string | null;
    missionImpactScore: number | null;
    missionFunction?: string | null;
    essentialService?: string | null;
    businessImpactLevel?: string | null;
  }[];
}) {
  const [groupBy, setGroupBy] = useState<"risk" | "mission" | "service">("risk");

  if (assets.length === 0) {
    return (
      <div className="text-center py-8 text-zinc-500">
        <Target className="w-8 h-8 mx-auto mb-2 opacity-50" />
        <p className="text-sm">No scored assets found. Run a domain scan first.</p>
      </div>
    );
  }

  // Group assets
  const grouped = useMemo(() => {
    const groups: Record<string, typeof assets> = {};
    for (const a of assets) {
      const key = groupBy === "risk"
        ? (a.riskBand ?? "low")
        : groupBy === "mission"
        ? (a.missionFunction ?? "unclassified")
        : (a.essentialService ?? "unclassified");
      if (!groups[key]) groups[key] = [];
      groups[key].push(a);
    }
    return Object.entries(groups).sort(([, a], [, b]) => b.length - a.length);
  }, [assets, groupBy]);

  return (
    <div className="space-y-4">
      {/* Group by selector */}
      <div className="flex items-center gap-2">
        <Label className="text-xs text-zinc-500">Group by:</Label>
        <div className="flex gap-1">
          {(["risk", "mission", "service"] as const).map((g) => (
            <Button
              key={g} variant={groupBy === g ? "default" : "ghost"} size="sm"
              className={`h-6 text-[10px] ${groupBy === g ? "bg-cyan-600" : ""}`}
              onClick={() => setGroupBy(g)}
            >
              {g === "risk" ? "Risk Band" : g === "mission" ? "Mission Function" : "Essential Service"}
            </Button>
          ))}
        </div>
      </div>

      {/* Grouped heat map */}
      {grouped.map(([group, groupAssets]) => (
        <div key={group}>
          <div className="flex items-center gap-2 mb-2">
            <h4 className="text-xs font-semibold text-zinc-300 capitalize">
              {group.replace(/_/g, " ")}
            </h4>
            <Badge variant="outline" className="text-[9px]">{groupAssets.length}</Badge>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-2">
            {groupAssets.slice(0, 48).map((asset) => {
              const score = asset.hybridRiskScore ?? 0;
              const band = asset.riskBand ?? "low";
              const color = RISK_COLORS[band] ?? "#22c55e";
              const opacity = Math.max(0.3, score / 100);
              return (
                <div
                  key={asset.id}
                  className="relative p-2 rounded-lg border border-zinc-800 hover:border-zinc-600 transition-all cursor-default group"
                  style={{ backgroundColor: `${color}${Math.round(opacity * 40).toString(16).padStart(2, "0")}` }}
                >
                  <div className="text-[10px] font-mono text-zinc-300 truncate">
                    {asset.hostname || `Asset #${asset.id}`}
                  </div>
                  <div className="text-lg font-bold mt-0.5" style={{ color }}>{score}</div>
                  <div className="text-[9px] text-zinc-500">{asset.assetType || "unknown"}</div>
                  {asset.missionFunction && (
                    <div className="text-[8px] text-cyan-500/70 truncate mt-0.5">
                      {asset.missionFunction.replace(/_/g, " ")}
                    </div>
                  )}
                  {/* Tooltip */}
                  <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 hidden group-hover:block z-50">
                    <div className="bg-zinc-900 border border-zinc-700 rounded-lg p-2 shadow-xl text-xs whitespace-nowrap">
                      <div className="font-medium text-zinc-200">{asset.hostname}</div>
                      <div className="text-zinc-400">Risk: {score} ({band})</div>
                      <div className="text-zinc-400">Impact: {asset.missionImpactScore ?? "N/A"}</div>
                      {asset.missionFunction && (
                        <div className="text-cyan-400">Mission: {asset.missionFunction.replace(/_/g, " ")}</div>
                      )}
                      {asset.essentialService && (
                        <div className="text-amber-400">Service: {asset.essentialService.replace(/_/g, " ")}</div>
                      )}
                      {asset.businessImpactLevel && (
                        <div style={{ color: IMPACT_COLORS[asset.businessImpactLevel] || "#888" }}>
                          Impact Level: {asset.businessImpactLevel}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}

// ─── Mission Function Distribution Chart ──────────────────────────────
function MissionDistribution({
  assets,
}: {
  assets: { missionFunction?: string | null; businessImpactLevel?: string | null; hybridRiskScore: number | null }[];
}) {
  const distribution = useMemo(() => {
    const counts: Record<string, { count: number; avgRisk: number; totalRisk: number; impacts: Record<string, number> }> = {};
    for (const a of assets) {
      const mf = a.missionFunction || "unclassified";
      if (!counts[mf]) counts[mf] = { count: 0, avgRisk: 0, totalRisk: 0, impacts: {} };
      counts[mf].count++;
      counts[mf].totalRisk += a.hybridRiskScore ?? 0;
      const impact = a.businessImpactLevel || "unknown";
      counts[mf].impacts[impact] = (counts[mf].impacts[impact] || 0) + 1;
    }
    return Object.entries(counts)
      .map(([mf, data]) => ({
        missionFunction: mf,
        count: data.count,
        avgRisk: Math.round(data.totalRisk / data.count),
        impacts: data.impacts,
      }))
      .sort((a, b) => b.avgRisk - a.avgRisk);
  }, [assets]);

  if (distribution.length === 0) return null;

  const maxCount = Math.max(...distribution.map((d) => d.count));

  return (
    <div className="space-y-2">
      {distribution.map((d) => (
        <div key={d.missionFunction} className="flex items-center gap-3">
          <div className="w-40 text-[10px] text-zinc-400 truncate capitalize">
            {d.missionFunction.replace(/_/g, " ")}
          </div>
          <div className="flex-1 relative h-5 bg-zinc-800/50 rounded overflow-hidden">
            <div
              className="absolute inset-y-0 left-0 rounded"
              style={{
                width: `${(d.count / maxCount) * 100}%`,
                backgroundColor: d.avgRisk >= 85 ? "#ef4444" : d.avgRisk >= 65 ? "#f97316" : d.avgRisk >= 40 ? "#eab308" : "#22c55e",
                opacity: 0.6,
              }}
            />
            <div className="absolute inset-0 flex items-center px-2">
              <span className="text-[10px] font-mono text-zinc-200">{d.count} assets</span>
            </div>
          </div>
          <div className="w-16 text-right">
            <span className="text-xs font-mono" style={{
              color: d.avgRisk >= 85 ? "#ef4444" : d.avgRisk >= 65 ? "#f97316" : d.avgRisk >= 40 ? "#eab308" : "#22c55e",
            }}>
              {d.avgRisk}
            </span>
          </div>
        </div>
      ))}
    </div>
  );
}

// ─── Main Page ─────────────────────────────────────────────────────────
export default function ScoringHub() {
  const [activeTab, setActiveTab] = useState("profiles");
  const [selectedProfileId, setSelectedProfileId] = useState<number | undefined>();

  // Industry Baselines + FIPS 199 state
  type Fips199Level = "low" | "moderate" | "high";
  type IndustryVertical = "Corporate_Enterprise" | "Industrial_OT_Manufacturing" | "Government_Federal_State" | "Healthcare" | "Financial_Services" | "Energy_Utilities";
  type AssetTierType = "Tier_1_Strategic" | "Tier_2_Operational" | "Tier_3_Tactical";
  const [selectedIndustry, setSelectedIndustry] = useState<IndustryVertical>("Corporate_Enterprise");
  const [selectedTier, setSelectedTier] = useState<AssetTierType>("Tier_1_Strategic");
  const [fips199Custom, setFips199Custom] = useState<{
    access:  { confidentiality: Fips199Level; integrity: Fips199Level; availability: Fips199Level };
    storage: { confidentiality: Fips199Level; integrity: Fips199Level; availability: Fips199Level };
    transit: { confidentiality: Fips199Level; integrity: Fips199Level; availability: Fips199Level };
  } | null>(null);
  const [fips199UseDefaults, setFips199UseDefaults] = useState(true);
  const [selectedScanId, setSelectedScanId] = useState<number | undefined>();
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [showSimulator, setShowSimulator] = useState(false);
  const [timelineAssetId, setTimelineAssetId] = useState<number | undefined>();

  // CVSS v4.0 Calculator state
  const [cvssMetrics, setCvssMetrics] = useState({
    AV: "N" as "N"|"A"|"L"|"P", AC: "L" as "L"|"H", AT: "N" as "N"|"P",
    PR: "N" as "N"|"L"|"H", UI: "N" as "N"|"P"|"A",
    VC: "H" as "N"|"L"|"H", VI: "H" as "N"|"L"|"H", VA: "H" as "N"|"L"|"H",
    SC: "N" as "N"|"L"|"H", SI: "N" as "N"|"L"|"H", SA: "N" as "N"|"L"|"H",
    E: "X" as "X"|"A"|"P"|"U",
    CR: "X" as "X"|"H"|"M"|"L", IR: "X" as "X"|"H"|"M"|"L", AR: "X" as "X"|"H"|"M"|"L",
    S: "X" as "X"|"N"|"P", AU: "X" as "X"|"N"|"Y",
    R: "X" as "X"|"A"|"U"|"I", V: "X" as "X"|"D"|"C", RE: "X" as "X"|"L"|"M"|"H",
  });
  const [cvssVectorInput, setCvssVectorInput] = useState("");
  const [cvssApplyAssetId, setCvssApplyAssetId] = useState<number | undefined>();

  // Profile form state
  const [profileForm, setProfileForm] = useState({
    name: "", description: "", presetKey: "",
    wCriticality: 2.0, wAccessibility: 1.5, wRecuperability: 1.0,
    wVulnerability: 1.5, wEffect: 1.5, wRecognizability: 0.5,
    wScope: 1.5, wHandling: 1.0, wOperationalImpact: 2.0,
    wCascadingEffects: 1.5, wKnowledge: 1.0,
    carverWeight: 0.4, shockWeight: 0.3, cvssWeight: 0.3,
    criticalThreshold: 85, highThreshold: 65, mediumThreshold: 40,
  });

  // Simulator state
  const [simInput, setSimInput] = useState({
    carver: { criticality: 5, accessibility: 5, recuperability: 5, vulnerability: 5, effect: 5, recognizability: 5 },
    shock: { scope: 5, handling: 5, operationalImpact: 5, cascadingEffects: 5, knowledge: 5 },
    cvssEstimate: 5, exposure: 0.5, confidence: 0.7, confirmedVulnScore: 50,
    missionFunction: "public_facing_services",
    essentialService: "general_server",
    businessImpactLevel: "moderate",
  });

  // Industry Baselines queries
  const industryVerticalsQ = trpc.scoring.getIndustryVerticals.useQuery();
  const industryTierQ = trpc.scoring.getIndustryTierBreakdown.useQuery(
    { industry: selectedIndustry },
    { enabled: !!selectedIndustry }
  );
  const fips199DefaultsQ = trpc.scoring.getFips199Defaults.useQuery(
    { industry: selectedIndustry, tier: selectedTier },
    { enabled: !!selectedIndustry && !!selectedTier }
  );
  const computeFips199M = trpc.scoring.computeFips199.useMutation({
    onSuccess: () => toast.success("FIPS 199 adjustments computed"),
    onError: (e) => toast.error(e.message),
  });

  // Queries
  const profilesQ = trpc.scoring.listProfiles.useQuery();
  const presetsQ = trpc.scoring.getPresets.useQuery();
  const scansQ = trpc.scoring.listScoredScans.useQuery();
  const taxonomyQ = trpc.scoring.getTaxonomy.useQuery();
  const heatMapQ = trpc.scoring.getHeatMapData.useQuery(
    { scanId: selectedScanId! },
    { enabled: !!selectedScanId }
  );
  const simQ = trpc.scoring.simulateScore.useQuery(
    { ...simInput, profileId: selectedProfileId },
    { enabled: showSimulator }
  );
  const auditQ = trpc.scoring.getAuditLog.useQuery(
    { scanId: selectedScanId, limit: 50 },
    { enabled: !!selectedScanId }
  );
  const carverRefQ = trpc.scoring.getCarverReference.useQuery();
  const discoveryTriggersQ = trpc.scoring.getDiscoveryTriggers.useQuery();
  const cvssParseQ = trpc.scoring.parseCvssV4.useQuery(
    { vector: cvssVectorInput },
    { enabled: cvssVectorInput.startsWith("CVSS:4.0/") }
  );
  const cvssBuildQ = trpc.scoring.buildCvssV4Vector.useQuery(cvssMetrics);
  const timelineQ = trpc.scoring.getAssetScoringTimeline.useQuery(
    { assetId: timelineAssetId!, limit: 50 },
    { enabled: !!timelineAssetId }
  );

  // Mutations
  const createProfile = trpc.scoring.createProfile.useMutation({
    onSuccess: () => {
      toast.success("Scoring profile created");
      profilesQ.refetch();
      setShowCreateDialog(false);
    },
    onError: (e: any) => toast.error(e.message),
  });
  const deleteProfile = trpc.scoring.deleteProfile.useMutation({
    onSuccess: () => {
      toast.success("Profile deleted");
      profilesQ.refetch();
    },
  });
  const batchRescore = trpc.scoring.batchRescore.useMutation({
    onSuccess: (data: any) => {
      toast.success(`Re-scored ${data.scored} assets`);
      heatMapQ.refetch();
    },
    onError: (e: any) => toast.error(e.message),
  });
  const classifyAndRescore = trpc.scoring.classifyAndRescore.useMutation({
    onSuccess: (data: any) => {
      toast.success(`Classified ${data.classified} assets, re-scored ${data.scored}`);
      heatMapQ.refetch();
    },
    onError: (e: any) => toast.error(e.message),
  });
  const applyCvssV4 = trpc.scoring.applyCvssV4ToAsset.useMutation({
    onSuccess: (data: any) => {
      toast.success(`CVSS v4.0 applied — score ${data.hybridRiskScore} (${data.riskBand}) Δ${data.delta > 0 ? "+" : ""}${data.delta}`);
      heatMapQ.refetch();
    },
    onError: (e: any) => toast.error(e.message),
  });

  // Apply preset to form
  const applyPreset = (key: string) => {
    const preset = presetsQ.data?.find((p: any) => p.key === key);
    if (!preset) return;
    const p = preset.profile;
    setProfileForm((prev) => ({
      ...prev,
      presetKey: key,
      wCriticality: p.carverWeights.criticality,
      wAccessibility: p.carverWeights.accessibility,
      wRecuperability: p.carverWeights.recuperability,
      wVulnerability: p.carverWeights.vulnerability,
      wEffect: p.carverWeights.effect,
      wRecognizability: p.carverWeights.recognizability,
      wScope: p.shockWeights.scope,
      wHandling: p.shockWeights.handling,
      wOperationalImpact: p.shockWeights.operationalImpact,
      wCascadingEffects: p.shockWeights.cascadingEffects,
      wKnowledge: p.shockWeights.knowledge,
      carverWeight: p.carverWeight,
      shockWeight: p.shockWeight,
      cvssWeight: p.cvssWeight,
      criticalThreshold: p.criticalThreshold,
      highThreshold: p.highThreshold,
      mediumThreshold: p.mediumThreshold,
    }));
  };

  const simResult = simQ.data;

  return (
    <AppShell activePath="/scoring">
      <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-zinc-100 flex items-center gap-2">
            <Crosshair className="w-6 h-6 text-cyan-400" />
            Adaptive Risk Scoring Engine
          </h1>
            <p className="text-sm text-muted-foreground mt-1 max-w-3xl">Central dashboard for all risk scoring methodologies used across the platform. View and configure how assets, vulnerabilities, and findings are scored — including CVSS, CARVER, SHOCK, and hybrid risk calculations. Compare scoring models side-by-side, adjust weighting factors, and see how score changes propagate across your assessments. Use this to ensure consistent, defensible risk prioritization across all engagements.</p>
          <p className="text-sm text-zinc-400 mt-1">
            Mission-aware hybrid scoring with dynamic re-assessment during discovery
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => {
            toast.info('Select an asset in the Dynamic Scoring Timeline tab to export its scoring events.');
            setActiveTab('timeline');
          }}>
            <Download className="w-4 h-4 mr-1" />
            Export Timeline
          </Button>
          <Button variant="outline" size="sm" onClick={() => setShowSimulator(!showSimulator)}>
            <Gauge className="w-4 h-4 mr-1" />
            {showSimulator ? "Hide" : "Show"} Simulator
          </Button>
          <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
            <DialogTrigger asChild>
              <Button size="sm" className="bg-cyan-600 hover:bg-cyan-700">
                <Plus className="w-4 h-4 mr-1" /> New Profile
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
              <DialogHeader>
                <DialogTitle>Create Scoring Profile</DialogTitle>
                <DialogDescription>
                  Configure factor weights for a specific engagement type or industry.
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4 mt-4">
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <Label className="text-xs">Profile Name</Label>
                    <Input
                      value={profileForm.name}
                      onChange={(e) => setProfileForm((p) => ({ ...p, name: e.target.value }))}
                      placeholder="e.g., Healthcare Assessment Q1"
                    />
                  </div>
                  <div>
                    <Label className="text-xs">Start from Preset</Label>
                    <Select onValueChange={applyPreset}>
                      <SelectTrigger><SelectValue placeholder="Select preset..." /></SelectTrigger>
                      <SelectContent>
                        {presetsQ.data?.map((p: any) => (
                          <SelectItem key={p.key} value={p.key}>{p.name}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <div>
                  <Label className="text-xs">Description</Label>
                  <Input
                    value={profileForm.description}
                    onChange={(e) => setProfileForm((p) => ({ ...p, description: e.target.value }))}
                    placeholder="Describe the engagement objective..."
                  />
                </div>

                {/* CARVER Weights */}
                <div>
                  <h4 className="text-sm font-semibold text-cyan-400 flex items-center gap-1 mb-2">
                    <Target className="w-4 h-4" /> CARVER Factor Weights
                  </h4>
                  <div className="grid grid-cols-2 gap-x-4 gap-y-2">
                    <WeightSlider label="Criticality" value={profileForm.wCriticality} onChange={(v) => setProfileForm((p) => ({ ...p, wCriticality: v }))} description="Mission-critical importance to org operations" color="cyan" />
                    <WeightSlider label="Accessibility" value={profileForm.wAccessibility} onChange={(v) => setProfileForm((p) => ({ ...p, wAccessibility: v }))} description="Ease of attacker access to the target" color="cyan" />
                    <WeightSlider label="Recuperability" value={profileForm.wRecuperability} onChange={(v) => setProfileForm((p) => ({ ...p, wRecuperability: v }))} description="Time to recover after successful attack" color="cyan" />
                    <WeightSlider label="Vulnerability" value={profileForm.wVulnerability} onChange={(v) => setProfileForm((p) => ({ ...p, wVulnerability: v }))} description="Known vulnerability exposure level" color="cyan" />
                    <WeightSlider label="Effect" value={profileForm.wEffect} onChange={(v) => setProfileForm((p) => ({ ...p, wEffect: v }))} description="Magnitude of impact from successful attack" color="cyan" />
                    <WeightSlider label="Recognizability" value={profileForm.wRecognizability} onChange={(v) => setProfileForm((p) => ({ ...p, wRecognizability: v }))} description="Ease of identifying the target" color="cyan" />
                  </div>
                </div>

                {/* Shock Weights */}
                <div>
                  <h4 className="text-sm font-semibold text-amber-400 flex items-center gap-1 mb-2">
                    <Flame className="w-4 h-4" /> Shock Factor Weights
                  </h4>
                  <div className="grid grid-cols-2 gap-x-4 gap-y-2">
                    <WeightSlider label="Scope" value={profileForm.wScope} onChange={(v) => setProfileForm((p) => ({ ...p, wScope: v }))} description="Blast radius of compromise across systems" color="amber" />
                    <WeightSlider label="Handling" value={profileForm.wHandling} onChange={(v) => setProfileForm((p) => ({ ...p, wHandling: v }))} description="Incident response difficulty and complexity" color="amber" />
                    <WeightSlider label="Operational Impact" value={profileForm.wOperationalImpact} onChange={(v) => setProfileForm((p) => ({ ...p, wOperationalImpact: v }))} description="Business disruption severity" color="amber" />
                    <WeightSlider label="Cascading Effects" value={profileForm.wCascadingEffects} onChange={(v) => setProfileForm((p) => ({ ...p, wCascadingEffects: v }))} description="Failure propagation to dependent systems" color="amber" />
                    <WeightSlider label="Knowledge" value={profileForm.wKnowledge} onChange={(v) => setProfileForm((p) => ({ ...p, wKnowledge: v }))} description="Specialized knowledge required for attack" color="amber" />
                  </div>
                </div>

                {/* Meta Weights */}
                <div>
                  <h4 className="text-sm font-semibold text-violet-400 flex items-center gap-1 mb-2">
                    <Activity className="w-4 h-4" /> Composite Blend
                  </h4>
                  <div className="grid grid-cols-3 gap-3">
                    <MetaSlider label="CARVER" value={profileForm.carverWeight} onChange={(v) => setProfileForm((p) => ({ ...p, carverWeight: v }))} color="#06b6d4" />
                    <MetaSlider label="Shock" value={profileForm.shockWeight} onChange={(v) => setProfileForm((p) => ({ ...p, shockWeight: v }))} color="#f59e0b" />
                    <MetaSlider label="CVSS" value={profileForm.cvssWeight} onChange={(v) => setProfileForm((p) => ({ ...p, cvssWeight: v }))} color="#8b5cf6" />
                  </div>
                </div>

                {/* Thresholds */}
                <div>
                  <h4 className="text-sm font-semibold text-zinc-300 mb-2">Risk Band Thresholds</h4>
                  <div className="grid grid-cols-3 gap-3">
                    <div>
                      <Label className="text-xs text-red-400">Critical &ge;</Label>
                      <Input type="number" min={0} max={100} value={profileForm.criticalThreshold}
                        onChange={(e) => setProfileForm((p) => ({ ...p, criticalThreshold: parseInt(e.target.value) || 85 }))}
                      />
                    </div>
                    <div>
                      <Label className="text-xs text-orange-400">High &ge;</Label>
                      <Input type="number" min={0} max={100} value={profileForm.highThreshold}
                        onChange={(e) => setProfileForm((p) => ({ ...p, highThreshold: parseInt(e.target.value) || 65 }))}
                      />
                    </div>
                    <div>
                      <Label className="text-xs text-yellow-400">Medium &ge;</Label>
                      <Input type="number" min={0} max={100} value={profileForm.mediumThreshold}
                        onChange={(e) => setProfileForm((p) => ({ ...p, mediumThreshold: parseInt(e.target.value) || 40 }))}
                      />
                    </div>
                  </div>
                </div>

                <Button
                  className="w-full bg-cyan-600 hover:bg-cyan-700"
                  onClick={() => createProfile.mutate(profileForm)}
                  disabled={!profileForm.name || createProfile.isPending}
                >
                  <Save className="w-4 h-4 mr-1" />
                  {createProfile.isPending ? "Creating..." : "Create Profile"}
                </Button>
              </div>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Simulator Panel */}
      {showSimulator && (
        <Card className="border-cyan-500/30 bg-zinc-900/50">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <Gauge className="w-4 h-4 text-cyan-400" />
              Interactive Scoring Simulator
            </CardTitle>
            <CardDescription className="text-xs">
              Adjust factor scores, mission function, and essential service to see how the hybrid risk score changes.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
              {/* CARVER Inputs */}
              <div className="space-y-3">
                <h4 className="text-xs font-semibold text-cyan-400 uppercase tracking-wider">CARVER Factors</h4>
                {(["criticality", "accessibility", "recuperability", "vulnerability", "effect", "recognizability"] as const).map((key) => (
                  <div key={key} className="flex items-center gap-2">
                    <Label className="text-xs text-zinc-400 w-24 capitalize">{key}</Label>
                    <input type="range" min="0" max="10" step="1" value={simInput.carver[key]}
                      onChange={(e) => setSimInput((p) => ({ ...p, carver: { ...p.carver, [key]: parseInt(e.target.value) } }))}
                      className="flex-1 accent-cyan-500"
                    />
                    <span className="text-xs font-mono text-zinc-300 w-6 text-right">{simInput.carver[key]}</span>
                  </div>
                ))}
              </div>
              {/* Shock Inputs */}
              <div className="space-y-3">
                <h4 className="text-xs font-semibold text-amber-400 uppercase tracking-wider">Shock Factors</h4>
                {(["scope", "handling", "operationalImpact", "cascadingEffects", "knowledge"] as const).map((key) => (
                  <div key={key} className="flex items-center gap-2">
                    <Label className="text-xs text-zinc-400 w-24 capitalize">{key.replace(/([A-Z])/g, " $1")}</Label>
                    <input type="range" min="0" max="10" step="1" value={simInput.shock[key]}
                      onChange={(e) => setSimInput((p) => ({ ...p, shock: { ...p.shock, [key]: parseInt(e.target.value) } }))}
                      className="flex-1 accent-amber-500"
                    />
                    <span className="text-xs font-mono text-zinc-300 w-6 text-right">{simInput.shock[key]}</span>
                  </div>
                ))}
                <div className="pt-2 space-y-2">
                  <div className="flex items-center gap-2">
                    <Label className="text-xs text-zinc-400 w-24">CVSS Est.</Label>
                    <input type="range" min="0" max="10" step="0.5" value={simInput.cvssEstimate}
                      onChange={(e) => setSimInput((p) => ({ ...p, cvssEstimate: parseFloat(e.target.value) }))}
                      className="flex-1 accent-violet-500"
                    />
                    <span className="text-xs font-mono text-zinc-300 w-6 text-right">{simInput.cvssEstimate}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Label className="text-xs text-zinc-400 w-24">Vuln Score</Label>
                    <input type="range" min="0" max="100" step="5" value={simInput.confirmedVulnScore}
                      onChange={(e) => setSimInput((p) => ({ ...p, confirmedVulnScore: parseInt(e.target.value) }))}
                      className="flex-1 accent-red-500"
                    />
                    <span className="text-xs font-mono text-zinc-300 w-6 text-right">{simInput.confirmedVulnScore}</span>
                  </div>
                </div>
              </div>
              {/* Mission Context Inputs */}
              <div className="space-y-3">
                <h4 className="text-xs font-semibold text-emerald-400 uppercase tracking-wider flex items-center gap-1">
                  <Building2 className="w-3 h-3" /> Mission Context
                </h4>
                <div>
                  <Label className="text-[10px] text-zinc-500">Mission Function</Label>
                  <Select value={simInput.missionFunction} onValueChange={(v) => setSimInput((p) => ({ ...p, missionFunction: v }))}>
                    <SelectTrigger className="h-8 text-xs"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {(taxonomyQ.data?.missionFunctions ?? []).map((mf: any) => (
                        <SelectItem key={mf.key ?? mf} value={mf.key ?? mf}>{(mf.label ?? mf.key ?? mf).toString().replace(/_/g, " ")}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label className="text-[10px] text-zinc-500">Essential Service</Label>
                  <Select value={simInput.essentialService} onValueChange={(v) => setSimInput((p) => ({ ...p, essentialService: v }))}>
                    <SelectTrigger className="h-8 text-xs"><SelectValue /></SelectTrigger>
                    <SelectContent>
                  {(taxonomyQ.data?.essentialServices ?? []).map((es: any) => (
                    <SelectItem key={es.key ?? es} value={es.key ?? es}>{(es.label ?? es.key ?? es).toString().replace(/_/g, " ")}</SelectItem>
                  ))}
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label className="text-[10px] text-zinc-500">Business Impact Level</Label>
                  <Select value={simInput.businessImpactLevel} onValueChange={(v) => setSimInput((p) => ({ ...p, businessImpactLevel: v }))}>
                    <SelectTrigger className="h-8 text-xs"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {["catastrophic", "severe", "significant", "moderate", "minimal"].map((l) => (
                        <SelectItem key={l} value={l}>
                          <span className="capitalize" style={{ color: IMPACT_COLORS[l] }}>{l}</span>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="bg-zinc-800/50 rounded-lg p-2 mt-2">
                  <div className="text-[9px] text-zinc-500 mb-1">Mission baselines apply floor scores:</div>
                  <div className="text-[10px] text-emerald-400">
                    Critical assets are never under-scored regardless of vulnerability data
                  </div>
                </div>
              </div>
              {/* Result */}
              <div className="space-y-4">
                <h4 className="text-xs font-semibold text-zinc-300 uppercase tracking-wider">Result</h4>
                {simResult ? (
                  <>
                    <div className="text-center">
                      <div className="text-5xl font-bold" style={{ color: RISK_COLORS[simResult.riskBand] }}>
                        {simResult.hybridRiskScore}
                      </div>
                      <Badge className={`mt-1 ${RISK_BG[simResult.riskBand]}`}>
                        {simResult.riskBand.toUpperCase()}
                      </Badge>
                    </div>
                    <div className="grid grid-cols-2 gap-2 text-xs">
                      <div className="bg-zinc-800/50 rounded p-2">
                        <div className="text-zinc-500">CARVER</div>
                        <div className="text-cyan-400 font-mono">{simResult.carverComposite}</div>
                      </div>
                      <div className="bg-zinc-800/50 rounded p-2">
                        <div className="text-zinc-500">Shock</div>
                        <div className="text-amber-400 font-mono">{simResult.shockComposite}</div>
                      </div>
                      <div className="bg-zinc-800/50 rounded p-2">
                        <div className="text-zinc-500">Impact</div>
                        <div className="text-violet-400 font-mono">{simResult.impactScore}</div>
                      </div>
                      <div className="bg-zinc-800/50 rounded p-2">
                        <div className="text-zinc-500">Likelihood</div>
                        <div className="text-rose-400 font-mono">{simResult.likelihoodScore}</div>
                      </div>
                    </div>
                    <RadarChart factors={simResult.factorContributions} />
                  </>
                ) : (
                  <div className="text-center py-8 text-zinc-500 text-sm">
                    Adjust factors to see results...
                  </div>
                )}
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Main Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="bg-zinc-800/50">
          <TabsTrigger value="profiles">
            <Shield className="w-4 h-4 mr-1" /> Profiles
          </TabsTrigger>
          <TabsTrigger value="heatmap">
            <BarChart3 className="w-4 h-4 mr-1" /> Heat Map
          </TabsTrigger>
          <TabsTrigger value="mission">
            <Building2 className="w-4 h-4 mr-1" /> Mission Functions
          </TabsTrigger>
          <TabsTrigger value="cvss4">
            <Zap className="w-4 h-4 mr-1" /> CVSS v4.0
          </TabsTrigger>
          <TabsTrigger value="carver-ref">
            <Target className="w-4 h-4 mr-1" /> CARVER Matrix
          </TabsTrigger>
          <TabsTrigger value="timeline">
            <TrendingUp className="w-4 h-4 mr-1" /> Scoring Timeline
          </TabsTrigger>
          <TabsTrigger value="audit">
            <Eye className="w-4 h-4 mr-1" /> Audit Log
          </TabsTrigger>
          <TabsTrigger value="industry">
            <Building2 className="w-4 h-4 mr-1" /> Industry Baselines
          </TabsTrigger>
          <TabsTrigger value="fips199">
            <Lock className="w-4 h-4 mr-1" /> FIPS 199
          </TabsTrigger>
          <TabsTrigger value="carver-module">
            <Crosshair className="w-4 h-4 mr-1" /> CARVER Module
          </TabsTrigger>
        </TabsList>

        {/* Profiles Tab */}
        <TabsContent value="profiles" className="space-y-4">
          {/* Preset Templates */}
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm">Industry Preset Templates</CardTitle>
              <CardDescription className="text-xs">
                Pre-configured weight profiles optimized for specific industries and engagement types.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {presetsQ.data?.map((preset: any) => (
                  <div key={preset.key} className="bg-zinc-800/50 rounded-lg p-3 border border-zinc-700/50 hover:border-cyan-500/30 transition-colors">
                    <div className="flex items-center justify-between mb-1">
                      <h4 className="text-sm font-medium text-zinc-200">{preset.name}</h4>
                      <Button
                        variant="ghost" size="sm"
                        className="h-6 text-xs text-cyan-400 hover:text-cyan-300"
                        onClick={() => {
                          applyPreset(preset.key);
                          setProfileForm((p) => ({ ...p, name: preset.name }));
                          setShowCreateDialog(true);
                        }}
                      >
                        <Copy className="w-3 h-3 mr-1" /> Use
                      </Button>
                    </div>
                    <p className="text-[10px] text-zinc-500 leading-relaxed">{preset.description}</p>
                    <div className="flex gap-1 mt-2">
                      <Badge variant="outline" className="text-[9px] border-cyan-500/30 text-cyan-400">
                        CARVER {(preset.profile.carverWeight * 100).toFixed(0)}%
                      </Badge>
                      <Badge variant="outline" className="text-[9px] border-amber-500/30 text-amber-400">
                        Shock {(preset.profile.shockWeight * 100).toFixed(0)}%
                      </Badge>
                      <Badge variant="outline" className="text-[9px] border-violet-500/30 text-violet-400">
                        CVSS {(preset.profile.cvssWeight * 100).toFixed(0)}%
                      </Badge>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Custom Profiles */}
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm">Custom Profiles</CardTitle>
            </CardHeader>
            <CardContent>
              {!profilesQ.data?.length ? (
                <div className="text-center py-8 text-zinc-500">
                  <Shield className="w-8 h-8 mx-auto mb-2 opacity-50" />
                  <p className="text-sm">No custom profiles yet. Create one from a preset or from scratch.</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {profilesQ.data.map((p: any) => (
                    <div key={p.id} className="flex items-center justify-between bg-zinc-800/50 rounded-lg p-3 border border-zinc-700/50">
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium text-zinc-200">{p.name}</span>
                          {p.isDefault && <Badge className="text-[9px] bg-cyan-500/20 text-cyan-400">Default</Badge>}
                        </div>
                        <p className="text-[10px] text-zinc-500 mt-0.5">{p.description || "No description"}</p>
                        <div className="flex gap-1 mt-1">
                          <Badge variant="outline" className="text-[9px] border-cyan-500/30 text-cyan-400">
                            CARVER {((p.carverWeight ?? 0.4) * 100).toFixed(0)}%
                          </Badge>
                          <Badge variant="outline" className="text-[9px] border-amber-500/30 text-amber-400">
                            Shock {((p.shockWeight ?? 0.3) * 100).toFixed(0)}%
                          </Badge>
                          <Badge variant="outline" className="text-[9px] border-violet-500/30 text-violet-400">
                            CVSS {((p.cvssWeight ?? 0.3) * 100).toFixed(0)}%
                          </Badge>
                        </div>
                      </div>
                      <div className="flex gap-1">
                        <Button variant="ghost" size="sm" className="h-7 text-xs text-zinc-400 hover:text-red-400"
                          onClick={() => deleteProfile.mutate({ id: p.id })}
                        >
                          <Trash2 className="w-3 h-3" />
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Heat Map Tab */}
        <TabsContent value="heatmap" className="space-y-4">
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between flex-wrap gap-2">
                <div>
                  <CardTitle className="text-sm">Asset Risk Heat Map</CardTitle>
                  <CardDescription className="text-xs">
                    Visual risk distribution with mission function grouping. Select a scan and optionally re-score.
                  </CardDescription>
                </div>
                <div className="flex gap-2 flex-wrap">
                  <Select onValueChange={(v) => setSelectedScanId(parseInt(v))}>
                    <SelectTrigger className="w-[220px] h-8 text-xs">
                      <SelectValue placeholder="Select scan..." />
                    </SelectTrigger>
                    <SelectContent>
                      {scansQ.data?.map((s: any) => (
                        <SelectItem key={s.id} value={String(s.id)}>
                          {s.domain} ({new Date(s.createdAt).toLocaleDateString()})
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <Select onValueChange={(v) => setSelectedProfileId(v === "default" ? undefined : parseInt(v))}>
                    <SelectTrigger className="w-[180px] h-8 text-xs">
                      <SelectValue placeholder="Default profile" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="default">Default Weights</SelectItem>
                      {profilesQ.data?.map((p: any) => (
                        <SelectItem key={p.id} value={String(p.id)}>{p.name}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  {selectedScanId && (
                    <>
                      <Button
                        size="sm" variant="outline" className="h-8 text-xs"
                        onClick={() => batchRescore.mutate({ scanId: selectedScanId, profileId: selectedProfileId })}
                        disabled={batchRescore.isPending}
                      >
                        <RefreshCw className={`w-3 h-3 mr-1 ${batchRescore.isPending ? "animate-spin" : ""}`} />
                        {batchRescore.isPending ? "Scoring..." : "Re-Score"}
                      </Button>
                      <Button
                        size="sm" className="h-8 text-xs bg-emerald-600 hover:bg-emerald-700"
                        onClick={() => classifyAndRescore.mutate({ scanId: selectedScanId, profileId: selectedProfileId })}
                        disabled={classifyAndRescore.isPending}
                      >
                        <Brain className={`w-3 h-3 mr-1 ${classifyAndRescore.isPending ? "animate-spin" : ""}`} />
                        {classifyAndRescore.isPending ? "Classifying..." : "AI Classify + Score"}
                      </Button>
                    </>
                  )}
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {!selectedScanId ? (
                <div className="text-center py-12 text-zinc-500">
                  <BarChart3 className="w-10 h-10 mx-auto mb-3 opacity-50" />
                  <p className="text-sm">Select a completed scan to view the risk heat map.</p>
                </div>
              ) : heatMapQ.isLoading ? (
                <div className="text-center py-12 text-zinc-500">
                  <RefreshCw className="w-6 h-6 mx-auto mb-2 animate-spin" />
                  <p className="text-sm">Loading heat map data...</p>
                </div>
              ) : heatMapQ.data ? (
                <div className="space-y-6">
                  {/* Stats bar */}
                  <div className="grid grid-cols-5 gap-3">
                    <div className="bg-zinc-800/50 rounded-lg p-3 text-center">
                      <div className="text-2xl font-bold text-zinc-200">{heatMapQ.data.stats.total}</div>
                      <div className="text-[10px] text-zinc-500">Total Assets</div>
                    </div>
                    <div className="bg-zinc-800/50 rounded-lg p-3 text-center">
                      <div className="text-2xl font-bold" style={{ color: RISK_COLORS.critical }}>
                        {heatMapQ.data.stats.distribution.critical}
                      </div>
                      <div className="text-[10px] text-red-400">Critical</div>
                    </div>
                    <div className="bg-zinc-800/50 rounded-lg p-3 text-center">
                      <div className="text-2xl font-bold" style={{ color: RISK_COLORS.high }}>
                        {heatMapQ.data.stats.distribution.high}
                      </div>
                      <div className="text-[10px] text-orange-400">High</div>
                    </div>
                    <div className="bg-zinc-800/50 rounded-lg p-3 text-center">
                      <div className="text-2xl font-bold" style={{ color: RISK_COLORS.medium }}>
                        {heatMapQ.data.stats.distribution.medium}
                      </div>
                      <div className="text-[10px] text-yellow-400">Medium</div>
                    </div>
                    <div className="bg-zinc-800/50 rounded-lg p-3 text-center">
                      <div className="text-2xl font-bold" style={{ color: RISK_COLORS.low }}>
                        {heatMapQ.data.stats.distribution.low}
                      </div>
                      <div className="text-[10px] text-green-400">Low</div>
                    </div>
                  </div>

                  {/* Mission Function Distribution */}
                  <Card className="bg-zinc-800/30 border-zinc-700/50">
                    <CardHeader className="pb-2">
                      <CardTitle className="text-xs flex items-center gap-1">
                        <Building2 className="w-3 h-3 text-emerald-400" />
                        Risk by Mission Function
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <MissionDistribution assets={heatMapQ.data.assets} />
                    </CardContent>
                  </Card>

                  {/* Heat map grid */}
                  <HeatMapGrid assets={heatMapQ.data.assets} />
                </div>
              ) : null}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Mission Functions Tab */}
        <TabsContent value="mission" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Mission Functions Reference */}
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Building2 className="w-4 h-4 text-emerald-400" />
                  Mission Functions
                </CardTitle>
                <CardDescription className="text-xs">
                  Organizational mission functions that drive criticality floor scores.
                  Assets classified under critical missions receive baseline scores that prevent under-scoring.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {(taxonomyQ.data?.missionFunctions ?? []).map((mf: any, i: number) => {
                    const key = mf.key ?? mf;
                    const label = mf.label ?? key;
                    const criticality = mf.baseline?.criticality ?? ([9, 8, 8, 7, 9, 7, 7, 6, 5, 4][i] ?? 5);
                    const color = criticality >= 8 ? "#ef4444" : criticality >= 6 ? "#f97316" : criticality >= 4 ? "#eab308" : "#22c55e";
                    return (
                      <div key={key} className="flex items-center gap-3 bg-zinc-800/30 rounded-lg p-2">
                        <div className="w-8 h-8 rounded-lg flex items-center justify-center text-xs font-bold" style={{ backgroundColor: `${color}20`, color }}>
                          {criticality}
                        </div>
                        <div className="flex-1">
                          <div className="text-xs font-medium text-zinc-200 capitalize">{String(label).replace(/_/g, " ")}</div>
                        </div>
                        <Badge variant="outline" className="text-[9px]" style={{ borderColor: `${color}50`, color }}>
                          Floor: {criticality}/10
                        </Badge>
                      </div>
                    );
                  })}
                </div>
              </CardContent>
            </Card>

            {/* Essential Services Reference */}
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Server className="w-4 h-4 text-cyan-400" />
                  Essential Services
                </CardTitle>
                <CardDescription className="text-xs">
                  Service-level baselines that provide granular CARVER/Shock adjustments.
                  Each service type has specific factor adjustments based on its role.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-1 max-h-[500px] overflow-y-auto">
                  {(taxonomyQ.data?.essentialServices ?? []).map((es: any) => {
                    const key = es.key ?? es;
                    const label = es.label ?? key;
                    const icons: Record<string, typeof Server> = {
                      sso: Shield, active_directory: Network, vpn: Network,
                      email: Zap, dns: Layers, database: Cpu,
                      payment_processing: Target, api_gateway: Layers, ci_cd: RefreshCw,
                      monitoring: Eye, backup: Save, customer_portal: FileSearch,
                    };
                    const Icon = icons[key] || Server;
                    return (
                      <div key={key} className="flex items-center gap-2 bg-zinc-800/20 rounded p-1.5 hover:bg-zinc-800/40 transition-colors">
                        <Icon className="w-3 h-3 text-cyan-400/60 shrink-0" />
                        <span className="text-[10px] text-zinc-300 capitalize flex-1">{String(label).replace(/_/g, " ")}</span>
                      </div>
                    );
                  })}
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Business Impact Levels */}
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                Business Impact Levels
              </CardTitle>
              <CardDescription className="text-xs">
                Impact levels are assigned during LLM classification based on asset purpose and organizational context.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-5 gap-3">
                {[
                  { level: "catastrophic", desc: "Total mission failure, existential threat to organization", mult: "2.0x" },
                  { level: "severe", desc: "Major operational disruption, significant financial loss", mult: "1.7x" },
                  { level: "significant", desc: "Notable impact on operations, moderate financial exposure", mult: "1.4x" },
                  { level: "moderate", desc: "Limited operational impact, manageable financial exposure", mult: "1.1x" },
                  { level: "minimal", desc: "Negligible operational impact, minimal financial exposure", mult: "1.0x" },
                ].map((item) => (
                  <div key={item.level} className="bg-zinc-800/50 rounded-lg p-3 border border-zinc-700/50 text-center">
                    <div className="text-lg font-bold capitalize" style={{ color: IMPACT_COLORS[item.level] }}>
                      {item.level}
                    </div>
                    <div className="text-[10px] text-zinc-500 mt-1 leading-relaxed">{item.desc}</div>
                    <Badge variant="outline" className="mt-2 text-[9px]" style={{ borderColor: `${IMPACT_COLORS[item.level]}50`, color: IMPACT_COLORS[item.level] }}>
                      Multiplier: {item.mult}
                    </Badge>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Device & Platform Types */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Cpu className="w-4 h-4 text-violet-400" />
                  Device Type Taxonomy
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-1.5">
                  {[
                    "server", "workstation", "network_device", "iot_device", "mobile_device",
                    "virtual_machine", "container", "cloud_instance", "embedded_system",
                    "industrial_control", "medical_device", "point_of_sale", "printer_mfp",
                    "voip_phone", "security_appliance", "storage_array", "unknown",
                  ].map((dt: string) => (
                    <Badge key={dt} variant="outline" className="text-[10px] text-violet-300 border-violet-500/30">
                      {dt.replace(/_/g, " ")}
                    </Badge>
                  ))}
                </div>
              </CardContent>
            </Card>
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Layers className="w-4 h-4 text-rose-400" />
                  Platform Type Taxonomy
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-1.5">
                  {[
                    "linux", "windows", "macos", "ios", "android", "freebsd",
                    "vmware_esxi", "kubernetes", "docker", "aws", "azure", "gcp",
                    "cisco_ios", "juniper_junos", "palo_alto_panos", "fortinet_fortios",
                    "custom_firmware", "rtos", "unknown",
                  ].map((pt: string) => (
                    <Badge key={pt} variant="outline" className="text-[10px] text-rose-300 border-rose-500/30">
                      {pt.replace(/_/g, " ")}
                    </Badge>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* ─── CVSS v4.0 Calculator Tab ────────────────────────────── */}
        <TabsContent value="cvss4" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Vector Builder */}
            <div className="lg:col-span-2 space-y-4">
              <Card className="bg-zinc-900/50 border-zinc-800">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Zap className="w-4 h-4 text-violet-400" />
                    CVSS v4.0 Vector Builder
                  </CardTitle>
                  <CardDescription className="text-xs">
                    Build or parse CVSS v4.0 vectors. The engine automatically translates CVSS metrics into CARVER factor adjustments.
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  {/* Parse existing vector */}
                  <div className="flex gap-2">
                    <Input
                      value={cvssVectorInput}
                      onChange={(e) => setCvssVectorInput(e.target.value)}
                      placeholder="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
                      className="font-mono text-xs"
                    />
                    <Button size="sm" variant="outline" onClick={() => {
                      if (cvssBuildQ.data?.vector) setCvssVectorInput(cvssBuildQ.data.vector);
                    }}>
                      <Copy className="w-3 h-3 mr-1" /> From Builder
                    </Button>
                  </div>

                  {/* Base Metrics */}
                  <div className="space-y-3">
                    <h4 className="text-xs font-semibold text-violet-400 uppercase tracking-wider">Base Metrics (Required)</h4>
                    <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                      {([
                        { key: "AV", label: "Attack Vector", opts: [["N","Network"],["A","Adjacent"],["L","Local"],["P","Physical"]] },
                        { key: "AC", label: "Attack Complexity", opts: [["L","Low"],["H","High"]] },
                        { key: "AT", label: "Attack Requirements", opts: [["N","None"],["P","Present"]] },
                        { key: "PR", label: "Privileges Required", opts: [["N","None"],["L","Low"],["H","High"]] },
                        { key: "UI", label: "User Interaction", opts: [["N","None"],["P","Passive"],["A","Active"]] },
                        { key: "VC", label: "Vuln. Confidentiality", opts: [["N","None"],["L","Low"],["H","High"]] },
                        { key: "VI", label: "Vuln. Integrity", opts: [["N","None"],["L","Low"],["H","High"]] },
                        { key: "VA", label: "Vuln. Availability", opts: [["N","None"],["L","Low"],["H","High"]] },
                        { key: "SC", label: "Sub. Confidentiality", opts: [["N","None"],["L","Low"],["H","High"]] },
                        { key: "SI", label: "Sub. Integrity", opts: [["N","None"],["L","Low"],["H","High"]] },
                        { key: "SA", label: "Sub. Availability", opts: [["N","None"],["L","Low"],["H","High"]] },
                      ] as { key: string; label: string; opts: string[][] }[]).map((m) => (
                        <div key={m.key}>
                          <Label className="text-[10px] text-zinc-500">{m.label}</Label>
                          <Select
                            value={(cvssMetrics as any)[m.key]}
                            onValueChange={(v) => setCvssMetrics((p) => ({ ...p, [m.key]: v }))}
                          >
                            <SelectTrigger className="h-7 text-xs"><SelectValue /></SelectTrigger>
                            <SelectContent>
                              {m.opts.map(([val, lbl]) => (
                                <SelectItem key={val} value={val}>{val}: {lbl}</SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Threat + Environmental + Supplemental */}
                  <div className="space-y-3">
                    <h4 className="text-xs font-semibold text-amber-400 uppercase tracking-wider">Threat / Environmental / Supplemental (Optional)</h4>
                    <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                      {([
                        { key: "E", label: "Exploit Maturity", opts: [["X","Not Defined"],["A","Attacked"],["P","PoC"],["U","Unreported"]] },
                        { key: "CR", label: "Conf. Requirement", opts: [["X","Not Defined"],["H","High"],["M","Medium"],["L","Low"]] },
                        { key: "IR", label: "Integ. Requirement", opts: [["X","Not Defined"],["H","High"],["M","Medium"],["L","Low"]] },
                        { key: "AR", label: "Avail. Requirement", opts: [["X","Not Defined"],["H","High"],["M","Medium"],["L","Low"]] },
                        { key: "S", label: "Safety", opts: [["X","Not Defined"],["N","Negligible"],["P","Present"]] },
                        { key: "AU", label: "Automatable", opts: [["X","Not Defined"],["N","No"],["Y","Yes"]] },
                        { key: "R", label: "Recovery", opts: [["X","Not Defined"],["A","Automatic"],["U","User"],["I","Irrecoverable"]] },
                        { key: "V", label: "Value Density", opts: [["X","Not Defined"],["D","Diffuse"],["C","Concentrated"]] },
                        { key: "RE", label: "Response Effort", opts: [["X","Not Defined"],["L","Low"],["M","Moderate"],["H","High"]] },
                      ] as { key: string; label: string; opts: string[][] }[]).map((m) => (
                        <div key={m.key}>
                          <Label className="text-[10px] text-zinc-500">{m.label}</Label>
                          <Select
                            value={(cvssMetrics as any)[m.key]}
                            onValueChange={(v) => setCvssMetrics((p) => ({ ...p, [m.key]: v }))}
                          >
                            <SelectTrigger className="h-7 text-xs"><SelectValue /></SelectTrigger>
                            <SelectContent>
                              {m.opts.map(([val, lbl]) => (
                                <SelectItem key={val} value={val}>{val}: {lbl}</SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Apply to Asset */}
                  <div className="flex items-center gap-2 pt-2 border-t border-zinc-800">
                    <Label className="text-xs text-zinc-400 shrink-0">Apply to Asset ID:</Label>
                    <Input
                      type="number" className="w-24 h-8 text-xs"
                      value={cvssApplyAssetId ?? ""}
                      onChange={(e) => setCvssApplyAssetId(e.target.value ? parseInt(e.target.value) : undefined)}
                      placeholder="#"
                    />
                    <Button
                      size="sm" className="bg-violet-600 hover:bg-violet-700 h-8 text-xs"
                      disabled={!cvssApplyAssetId || !cvssBuildQ.data?.vector || applyCvssV4.isPending}
                      onClick={() => {
                        if (cvssApplyAssetId && cvssBuildQ.data?.vector) {
                          applyCvssV4.mutate({
                            assetId: cvssApplyAssetId,
                            cvssV4Vector: cvssBuildQ.data.vector,
                            profileId: selectedProfileId,
                          });
                        }
                      }}
                    >
                      {applyCvssV4.isPending ? <RefreshCw className="w-3 h-3 mr-1 animate-spin" /> : <Zap className="w-3 h-3 mr-1" />}
                      Apply CVSS v4.0 & Re-Score
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Result Panel */}
            <div className="space-y-4">
              <Card className="bg-zinc-900/50 border-violet-500/30">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm">Computed Vector</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="bg-zinc-800/50 rounded-lg p-3">
                    <code className="text-[10px] text-violet-300 break-all font-mono">
                      {cvssBuildQ.data?.vector ?? "Building..."}
                    </code>
                  </div>
                  {cvssBuildQ.data?.parsed && (
                    <>
                      <div className="text-center">
                        <div className="text-4xl font-bold" style={{
                          color: cvssBuildQ.data.parsed.estimatedScore >= 9 ? "#ef4444"
                            : cvssBuildQ.data.parsed.estimatedScore >= 7 ? "#f97316"
                            : cvssBuildQ.data.parsed.estimatedScore >= 4 ? "#eab308" : "#22c55e"
                        }}>
                          {cvssBuildQ.data.parsed.estimatedScore.toFixed(1)}
                        </div>
                        <div className="text-[10px] text-zinc-500 mt-1">Estimated CVSS v4.0 Score</div>
                      </div>
                      <div className="grid grid-cols-2 gap-2 text-xs">
                        <div className="bg-zinc-800/50 rounded p-2">
                          <div className="text-zinc-500 text-[10px]">Nomenclature</div>
                          <div className="text-violet-400 font-mono">{cvssBuildQ.data.parsed.nomenclature ?? "N/A"}</div>
                        </div>
                        <div className="bg-zinc-800/50 rounded p-2">
                          <div className="text-zinc-500 text-[10px]">Severity</div>
                          <div className="text-rose-400 font-mono">{cvssBuildQ.data.parsed.severity ?? "N/A"}</div>
                        </div>
                      </div>
                    </>
                  )}
                </CardContent>
              </Card>

              {/* CARVER Feed-Through Preview */}
              {cvssVectorInput.startsWith("CVSS:4.0/") && cvssParseQ.data?.feedThrough && (
                <Card className="bg-zinc-900/50 border-cyan-500/30">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-sm flex items-center gap-2">
                      <ArrowRight className="w-4 h-4 text-cyan-400" />
                      CVSS → CARVER Feed-Through
                    </CardTitle>
                    <CardDescription className="text-[10px]">
                      Automatic CARVER factor adjustments derived from the CVSS v4.0 vector.
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      {Object.entries(cvssParseQ.data.feedThrough.carverAdjustments ?? {}).map(([key, val]) => (
                        <div key={key} className="flex items-center gap-2">
                          <span className="text-[10px] text-zinc-400 w-28 capitalize">{key}</span>
                          <div className="flex-1 h-2 bg-zinc-800 rounded-full overflow-hidden">
                            <div className="h-full bg-cyan-500 rounded-full" style={{ width: `${((val as number) / 10) * 100}%` }} />
                          </div>
                          <span className="text-xs font-mono text-cyan-400 w-6 text-right">{val as number}</span>
                        </div>
                      ))}
                      {Object.entries(cvssParseQ.data.feedThrough.shockAdjustments ?? {}).map(([key, val]) => (
                        <div key={key} className="flex items-center gap-2">
                          <span className="text-[10px] text-zinc-400 w-28 capitalize">{key.replace(/([A-Z])/g, " $1")}</span>
                          <div className="flex-1 h-2 bg-zinc-800 rounded-full overflow-hidden">
                            <div className="h-full bg-amber-500 rounded-full" style={{ width: `${((val as number) / 10) * 100}%` }} />
                          </div>
                          <span className="text-xs font-mono text-amber-400 w-6 text-right">{val as number}</span>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>
          </div>
        </TabsContent>

        {/* ─── CARVER Matrix Reference Tab ─────────────────────────────── */}
        <TabsContent value="carver-ref" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* CARVER Factors */}
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Crosshair className="w-4 h-4 text-cyan-400" />
                  CARVER Factors — FM 34-36 Digital Translation
                </CardTitle>
                <CardDescription className="text-xs">
                  Each factor from the US Army FM 34-36 targeting methodology translated to digital asset context.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {carverRefQ.data?.carver && Object.entries(carverRefQ.data.carver).map(([key, factor]: [string, any]) => (
                    <div key={key} className="bg-zinc-800/30 rounded-lg p-3 border border-zinc-700/50">
                      <div className="flex items-center justify-between mb-2">
                        <h5 className="text-xs font-semibold text-cyan-400">{factor.name}</h5>
                        <Badge variant="outline" className="text-[9px] border-cyan-500/30 text-cyan-300">
                          FM 34-36
                        </Badge>
                      </div>
                      <p className="text-[10px] text-zinc-400 mb-2 italic">"{factor.fm34_36}"</p>
                      <p className="text-[10px] text-zinc-300 mb-2">{factor.digital}</p>
                      <div className="space-y-1">
                        {factor.scale?.map((s: any, i: number) => (
                          <div key={i} className="flex gap-2 text-[9px]">
                            <Badge className="shrink-0 text-[8px] w-10 justify-center" style={{
                              backgroundColor: s.range[0] >= 9 ? "#ef444430" : s.range[0] >= 7 ? "#f9731630" : s.range[0] >= 5 ? "#eab30830" : s.range[0] >= 3 ? "#22c55e30" : "#64748b30",
                              color: s.range[0] >= 9 ? "#ef4444" : s.range[0] >= 7 ? "#f97316" : s.range[0] >= 5 ? "#eab308" : s.range[0] >= 3 ? "#22c55e" : "#94a3b8",
                            }}>
                              {s.range[0]}-{s.range[1]}
                            </Badge>
                            <span className="text-zinc-500">{s.digital}</span>
                          </div>
                        ))}
                      </div>
                      {factor.subFactors && (
                        <div className="flex flex-wrap gap-1 mt-2">
                          {factor.subFactors.map((sf: string) => (
                            <Badge key={sf} variant="outline" className="text-[8px] text-zinc-500 border-zinc-700">{sf}</Badge>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            {/* Shock Factors */}
            <div className="space-y-4">
              <Card className="bg-zinc-900/50 border-zinc-800">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Flame className="w-4 h-4 text-amber-400" />
                    Shock Factors — FDA Primer Digital Translation
                  </CardTitle>
                  <CardDescription className="text-xs">
                    Shock factors adapted from the FDA CARVER+Shock primer for cyber impact assessment.
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {carverRefQ.data?.shock && Object.entries(carverRefQ.data.shock).map(([key, factor]: [string, any]) => (
                      <div key={key} className="bg-zinc-800/30 rounded-lg p-3 border border-zinc-700/50">
                        <div className="flex items-center justify-between mb-2">
                          <h5 className="text-xs font-semibold text-amber-400">{factor.name}</h5>
                          <Badge variant="outline" className="text-[9px] border-amber-500/30 text-amber-300">
                            Shock
                          </Badge>
                        </div>
                        <p className="text-[10px] text-zinc-400 mb-2 italic">"{factor.original}"</p>
                        <p className="text-[10px] text-zinc-300 mb-2">{factor.digital}</p>
                        <div className="space-y-1">
                          {factor.scale?.map((s: any, i: number) => (
                            <div key={i} className="flex gap-2 text-[9px]">
                              <Badge className="shrink-0 text-[8px] w-10 justify-center" style={{
                                backgroundColor: s.range[0] >= 9 ? "#ef444430" : s.range[0] >= 7 ? "#f9731630" : s.range[0] >= 5 ? "#eab30830" : s.range[0] >= 3 ? "#22c55e30" : "#64748b30",
                                color: s.range[0] >= 9 ? "#ef4444" : s.range[0] >= 7 ? "#f97316" : s.range[0] >= 5 ? "#eab308" : s.range[0] >= 3 ? "#22c55e" : "#94a3b8",
                              }}>
                                {s.range[0]}-{s.range[1]}
                              </Badge>
                              <span className="text-zinc-500">{s.digital}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              {/* Criticality Tiers */}
              <Card className="bg-zinc-900/50 border-zinc-800">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Layers className="w-4 h-4 text-rose-400" />
                    Criticality Tiers (RTO-Aligned)
                  </CardTitle>
                  <CardDescription className="text-xs">
                    Five-tier system aligned to Recovery Time Objectives. Each tier sets minimum CARVER+Shock factor floors.
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {[1, 2, 3, 4, 5].map((tier) => {
                      const colors = ["#ef4444", "#f97316", "#eab308", "#22c55e", "#64748b"];
                      const names = ["Mission Critical", "Business Critical", "Business Important", "Administrative", "Non-Essential"];
                      const rtos = ["< 1 hour", "1–24 hours", "1–7 days", "> 7 days", "N/A"];
                      const mults = ["2.0x", "1.6x", "1.3x", "0.9x", "0.6x"];
                      return (
                        <div key={tier} className="flex items-center gap-3 bg-zinc-800/30 rounded-lg p-2">
                          <div className="w-8 h-8 rounded-lg flex items-center justify-center text-sm font-bold" style={{
                            backgroundColor: `${colors[tier - 1]}20`, color: colors[tier - 1],
                          }}>
                            T{tier}
                          </div>
                          <div className="flex-1">
                            <div className="text-xs font-medium text-zinc-200">{names[tier - 1]}</div>
                            <div className="text-[10px] text-zinc-500">RTO: {rtos[tier - 1]}</div>
                          </div>
                          <Badge variant="outline" className="text-[9px]" style={{
                            borderColor: `${colors[tier - 1]}50`, color: colors[tier - 1],
                          }}>
                            {mults[tier - 1]} multiplier
                          </Badge>
                        </div>
                      );
                    })}
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>
        </TabsContent>

        {/* ─── Dynamic Scoring Timeline Tab ─────────────────────────────── */}
        <TabsContent value="timeline" className="space-y-4">
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between flex-wrap gap-2">
                <div>
                  <CardTitle className="text-sm flex items-center gap-2">
                    <TrendingUp className="w-4 h-4 text-emerald-400" />
                    Dynamic Scoring Timeline
                  </CardTitle>
                  <CardDescription className="text-xs">
                    Track how asset risk scores evolve during discovery and enumeration as new intelligence emerges.
                  </CardDescription>
                </div>
                <div className="flex gap-2">
                  <Input
                    type="number" className="w-28 h-8 text-xs"
                    value={timelineAssetId ?? ""}
                    onChange={(e) => setTimelineAssetId(e.target.value ? parseInt(e.target.value) : undefined)}
                    placeholder="Asset ID"
                  />
                  {timelineQ.data && timelineQ.data.length > 0 && (
                    <Button variant="outline" size="sm" className="h-8 text-xs" onClick={() => {
                      exportScoringTimeline(`asset-${timelineAssetId}`, timelineQ.data!, 'csv');
                      toast.success(`Exported ${timelineQ.data!.length} scoring events`);
                    }}>
                      <Download className="w-3 h-3 mr-1" /> CSV
                    </Button>
                  )}
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {!timelineAssetId ? (
                <div className="text-center py-12 text-zinc-500">
                  <Clock className="w-10 h-10 mx-auto mb-3 opacity-50" />
                  <p className="text-sm">Enter an asset ID to view its scoring timeline.</p>
                  <p className="text-[10px] text-zinc-600 mt-1">Scores change dynamically as new CVEs, ports, KEV matches, and threat intelligence are discovered.</p>
                </div>
              ) : timelineQ.isLoading ? (
                <div className="text-center py-12 text-zinc-500">
                  <RefreshCw className="w-6 h-6 mx-auto mb-2 animate-spin" />
                  <p className="text-sm">Loading timeline...</p>
                </div>
              ) : !timelineQ.data?.length ? (
                <div className="text-center py-12 text-zinc-500">
                  <Clock className="w-8 h-8 mx-auto mb-2 opacity-50" />
                  <p className="text-sm">No scoring events found for this asset.</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {/* Score Evolution Chart (simplified SVG) */}
                  <div className="bg-zinc-800/30 rounded-lg p-4">
                    <h4 className="text-xs font-semibold text-zinc-300 mb-3">Score Evolution</h4>
                    <svg viewBox="0 0 800 200" className="w-full h-40">
                      {/* Grid lines */}
                      {[0, 25, 50, 75, 100].map((v) => (
                        <g key={v}>
                          <line x1="40" y1={180 - v * 1.6} x2="780" y2={180 - v * 1.6} stroke="#374151" strokeWidth="0.5" />
                          <text x="35" y={184 - v * 1.6} textAnchor="end" className="text-[9px] fill-zinc-600">{v}</text>
                        </g>
                      ))}
                      {/* Score line */}
                      <polyline
                        fill="none" stroke="#06b6d4" strokeWidth="2"
                        points={timelineQ.data.map((e: any, i: number) => {
                          const x = 40 + (i / Math.max(timelineQ.data.length - 1, 1)) * 740;
                          const y = 180 - (e.hybridRiskScore ?? 0) * 1.6;
                          return `${x},${y}`;
                        }).join(" ")}
                      />
                      {/* Score dots */}
                      {timelineQ.data.map((e: any, i: number) => {
                        const x = 40 + (i / Math.max(timelineQ.data.length - 1, 1)) * 740;
                        const y = 180 - (e.hybridRiskScore ?? 0) * 1.6;
                        const color = RISK_COLORS[e.riskBand ?? "low"];
                        return <circle key={i} cx={x} cy={y} r="4" fill={color} stroke="#1f2937" strokeWidth="1" />;
                      })}
                    </svg>
                  </div>

                  {/* Timeline Events */}
                  <div className="relative pl-6 space-y-3">
                    <div className="absolute left-2 top-0 bottom-0 w-0.5 bg-zinc-700" />
                    {timelineQ.data.map((entry: any, i: number) => {
                      const prevScore = i < timelineQ.data.length - 1 ? timelineQ.data[i + 1]?.hybridRiskScore ?? 0 : 0;
                      const delta = (entry.hybridRiskScore ?? 0) - prevScore;
                      return (
                        <div key={entry.id} className="relative">
                          <div className="absolute -left-4 top-1 w-3 h-3 rounded-full border-2 border-zinc-700" style={{
                            backgroundColor: RISK_COLORS[entry.riskBand ?? "low"],
                          }} />
                          <div className="bg-zinc-800/30 rounded-lg p-3 ml-2">
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-2">
                                <span className="text-lg font-bold" style={{ color: RISK_COLORS[entry.riskBand ?? "low"] }}>
                                  {entry.hybridRiskScore}
                                </span>
                                {delta !== 0 && (
                                  <Badge className={`text-[9px] ${delta > 0 ? "bg-red-500/20 text-red-400" : "bg-green-500/20 text-green-400"}`}>
                                    {delta > 0 ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                                    {delta > 0 ? "+" : ""}{delta}
                                  </Badge>
                                )}
                                <Badge className={`text-[9px] ${RISK_BG[entry.riskBand ?? "low"]}`}>
                                  {(entry.riskBand ?? "low").toUpperCase()}
                                </Badge>
                              </div>
                              <span className="text-[10px] text-zinc-600">
                                {entry.computedAt ? new Date(entry.computedAt).toLocaleString() : "N/A"}
                              </span>
                            </div>
                            <div className="grid grid-cols-4 gap-2 mt-2 text-[10px]">
                              <div><span className="text-zinc-500">Impact:</span> <span className="text-violet-400 font-mono">{entry.impactScore}</span></div>
                              <div><span className="text-zinc-500">Likelihood:</span> <span className="text-rose-400 font-mono">{entry.likelihoodScore}</span></div>
                              <div><span className="text-zinc-500">CVSS:</span> <span className="text-amber-400 font-mono">{entry.cvssEstimate ?? "N/A"}</span></div>
                              <div><span className="text-zinc-500">Mission:</span> <span className="text-emerald-400 font-mono">{entry.missionImpactScore ?? "N/A"}</span></div>
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Discovery Phase Triggers Reference */}
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm flex items-center gap-2">
                <Activity className="w-4 h-4 text-amber-400" />
                Discovery Phase Triggers
              </CardTitle>
              <CardDescription className="text-xs">
                Events during discovery and enumeration that automatically trigger score re-computation.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {(discoveryTriggersQ.data ?? []).map((trigger: any) => (
                  <div key={trigger.key} className="bg-zinc-800/30 rounded-lg p-3 border border-zinc-700/50">
                    <div className="flex items-center gap-2 mb-1">
                      <Zap className="w-3 h-3 text-amber-400" />
                      <span className="text-xs font-medium text-zinc-200 capitalize">{trigger.key.replace(/_/g, " ")}</span>
                    </div>
                    <p className="text-[10px] text-zinc-500">{trigger.description}</p>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Audit Log Tab */}
        <TabsContent value="audit" className="space-y-4">
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm">Scoring Audit Trail</CardTitle>
              <CardDescription className="text-xs">
                Immutable record of every scoring computation with full weight snapshots for reproducibility.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {!selectedScanId ? (
                <div className="text-center py-8 text-zinc-500 text-sm">
                  Select a scan from the Heat Map tab to view its audit log.
                </div>
              ) : !auditQ.data?.length ? (
                <div className="text-center py-8 text-zinc-500 text-sm">
                  No scoring events recorded for this scan yet.
                </div>
              ) : (
                <div className="space-y-1 max-h-[400px] overflow-y-auto">
                  {auditQ.data.map((entry: any) => (
                    <div key={entry.id} className="flex items-center gap-3 bg-zinc-800/30 rounded p-2 text-xs">
                      <div className="w-10 text-center">
                        <div className="text-lg font-bold" style={{ color: RISK_COLORS[entry.riskBand ?? "low"] }}>
                          {entry.hybridRiskScore}
                        </div>
                      </div>
                      <div className="flex-1">
                        <span className="text-zinc-400">Asset #{entry.assetId}</span>
                        <span className="text-zinc-600 mx-1">|</span>
                        <span className="text-zinc-500">
                          Impact: {entry.impactScore} / Likelihood: {entry.likelihoodScore}
                        </span>
                      </div>
                      <Badge className={`text-[9px] ${RISK_BG[entry.riskBand ?? "low"]}`}>
                        {(entry.riskBand ?? "low").toUpperCase()}
                      </Badge>
                      <span className="text-zinc-600 text-[10px]">
                        {entry.computedAt ? new Date(entry.computedAt).toLocaleString() : "N/A"}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ═══════════════════════════════════════════════════════════════ */}
        {/* INDUSTRY BASELINES TAB                                        */}
        {/* ═══════════════════════════════════════════════════════════════ */}
        <TabsContent value="industry" className="space-y-4">
          <Card className="bg-zinc-900/60 border-zinc-800">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-amber-400">
                <Building2 className="w-5 h-5" /> Industry Asset Tier Baselines
              </CardTitle>
              <CardDescription>
                View asset classification tiers and risk modifiers for each industry vertical.
                These baselines drive the hybrid scoring formula’s tier weighting and industry multipliers.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Industry Selector */}
              <div className="flex gap-4 items-end">
                <div className="flex-1">
                  <Label className="text-zinc-400 text-xs mb-1">Industry Vertical</Label>
                  <Select value={selectedIndustry} onValueChange={(v) => setSelectedIndustry(v as IndustryVertical)}>
                    <SelectTrigger className="bg-zinc-800 border-zinc-700">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="Corporate_Enterprise">Corporate / Enterprise</SelectItem>
                      <SelectItem value="Industrial_OT_Manufacturing">Industrial OT / Manufacturing</SelectItem>
                      <SelectItem value="Government_Federal_State">Government (Federal / State)</SelectItem>
                      <SelectItem value="Healthcare">Healthcare</SelectItem>
                      <SelectItem value="Financial_Services">Financial Services</SelectItem>
                      <SelectItem value="Energy_Utilities">Energy / Utilities</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="flex-1">
                  <Label className="text-zinc-400 text-xs mb-1">Asset Tier</Label>
                  <Select value={selectedTier} onValueChange={(v) => setSelectedTier(v as AssetTierType)}>
                    <SelectTrigger className="bg-zinc-800 border-zinc-700">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="Tier_1_Strategic">Tier 1 — Strategic (1.5x)</SelectItem>
                      <SelectItem value="Tier_2_Operational">Tier 2 — Operational (1.2x)</SelectItem>
                      <SelectItem value="Tier_3_Tactical">Tier 3 — Tactical (1.0x)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              {/* Tier Breakdown */}
              {industryTierQ.data && (
                <div className="space-y-3">
                  {Object.entries(industryTierQ.data.tiers).map(([tierKey, tierData]: [string, any]) => (
                    <div key={tierKey} className={`p-3 rounded-lg border ${
                      tierKey === "Tier_1_Strategic" ? "bg-red-500/5 border-red-500/20" :
                      tierKey === "Tier_2_Operational" ? "bg-amber-500/5 border-amber-500/20" :
                      "bg-zinc-800/50 border-zinc-700/50"
                    }`}>
                      <div className="flex items-center justify-between mb-2">
                        <span className={`font-semibold text-sm ${
                          tierKey === "Tier_1_Strategic" ? "text-red-400" :
                          tierKey === "Tier_2_Operational" ? "text-amber-400" :
                          "text-zinc-400"
                        }`}>
                          {tierKey.replace(/_/g, " ")}
                        </span>
                        <Badge variant="outline" className="text-[10px]">
                          Weight: {tierKey === "Tier_1_Strategic" ? "1.5x" : tierKey === "Tier_2_Operational" ? "1.2x" : "1.0x"}
                        </Badge>
                      </div>
                      <div className="flex flex-wrap gap-1.5">
                        {(tierData as string[]).map((asset: string) => (
                          <Badge key={asset} variant="outline" className="text-[10px] bg-zinc-800/60 border-zinc-700">
                            {asset}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* Industry Risk Modifiers */}
              <div className="mt-4 p-3 rounded-lg bg-zinc-800/40 border border-zinc-700/50">
                <h4 className="text-sm font-semibold text-zinc-300 mb-2 flex items-center gap-2">
                  <Activity className="w-4 h-4 text-amber-400" /> Industry Risk Modifiers
                </h4>
                <p className="text-xs text-zinc-500 mb-2">
                  These multipliers amplify risk scores based on industry-specific regulatory, safety, and systemic factors.
                </p>
                <div className="grid grid-cols-2 gap-2">
                  {industryTierQ.data?.modifiers && Object.entries(industryTierQ.data.modifiers).map(([key, val]) => (
                    <div key={key} className="flex items-center justify-between p-2 bg-zinc-900/60 rounded border border-zinc-700/30">
                      <span className="text-xs text-zinc-400">{key.replace(/_/g, " ").replace(" multiplier", "")}</span>
                      <span className="text-xs font-mono text-amber-400">{String(val)}x</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Auto-BIA Inference Rules */}
              <div className="mt-4 p-3 rounded-lg bg-zinc-800/40 border border-zinc-700/50">
                <h4 className="text-sm font-semibold text-zinc-300 mb-2 flex items-center gap-2">
                  <Brain className="w-4 h-4 text-cyan-400" /> Auto-BIA Inference Rules
                </h4>
                <p className="text-xs text-zinc-500 mb-2">
                  Signals detected from scan data automatically infer Business Impact Analysis multipliers.
                </p>
                <div className="space-y-1">
                  {[
                    { signal: "MX Record", asset: "Email Infrastructure", bia: 1.4 },
                    { signal: "SSO Endpoint", asset: "Identity Provider / SSO", bia: 1.5 },
                    { signal: "Payment Page", asset: "Customer-Facing Applications", bia: 1.45 },
                    { signal: "Admin Panel", asset: "Cloud Control Plane", bia: 1.5 },
                    { signal: "Database Port Exposure", asset: "Core Business Databases", bia: 1.5 },
                    { signal: "Git Repository", asset: "CI/CD Pipeline", bia: 1.35 },
                  ].map((rule) => (
                    <div key={rule.signal} className="flex items-center justify-between p-2 bg-zinc-900/40 rounded border border-zinc-700/20">
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className="text-[9px] bg-cyan-500/10 text-cyan-400 border-cyan-500/30">
                          {rule.signal}
                        </Badge>
                        <span className="text-xs text-zinc-400">→ {rule.asset}</span>
                      </div>
                      <span className="text-xs font-mono text-cyan-400">{rule.bia}x BIA</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Hybrid Formula Reference */}
              <div className="mt-4 p-3 rounded-lg bg-gradient-to-r from-amber-500/5 to-cyan-500/5 border border-zinc-700/50">
                <h4 className="text-sm font-semibold text-zinc-300 mb-2 flex items-center gap-2">
                  <Gauge className="w-4 h-4 text-amber-400" /> Enhanced Hybrid Formula
                </h4>
                <div className="font-mono text-xs text-zinc-300 bg-zinc-900/60 p-3 rounded border border-zinc-700/30">
                  <div>Score = ((CARVER/70 × <span className="text-amber-400">0.5</span>) + (CVSS/10 × <span className="text-cyan-400">0.3</span>) + (BIA × <span className="text-green-400">0.2</span>))</div>
                  <div className="ml-8">× TierWeight × ShockMultiplier × IndustryModifier × <span className="text-purple-400">FIPS199Multiplier</span></div>
                </div>
                <div className="grid grid-cols-4 gap-2 mt-2">
                  <div className="text-center p-2 bg-zinc-900/40 rounded">
                    <div className="text-[10px] text-zinc-500">CARVER</div>
                    <div className="text-sm font-mono text-amber-400">50%</div>
                  </div>
                  <div className="text-center p-2 bg-zinc-900/40 rounded">
                    <div className="text-[10px] text-zinc-500">CVSS</div>
                    <div className="text-sm font-mono text-cyan-400">30%</div>
                  </div>
                  <div className="text-center p-2 bg-zinc-900/40 rounded">
                    <div className="text-[10px] text-zinc-500">BIA</div>
                    <div className="text-sm font-mono text-green-400">20%</div>
                  </div>
                  <div className="text-center p-2 bg-zinc-900/40 rounded">
                    <div className="text-[10px] text-zinc-500">FIPS 199</div>
                    <div className="text-sm font-mono text-purple-400">× Mult</div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ═══════════════════════════════════════════════════════════════ */}
        {/* FIPS 199 SECURITY CATEGORIZATION TAB                           */}
        {/* ═══════════════════════════════════════════════════════════════ */}
        <TabsContent value="fips199" className="space-y-4">
          <Card className="bg-zinc-900/60 border-zinc-800">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-purple-400">
                <Lock className="w-5 h-5" /> FIPS 199 Security Categorization
              </CardTitle>
              <CardDescription>
                Categorize information types across three lifecycle states: <strong>Access</strong> (data in use),
                <strong> Storage</strong> (data at rest), and <strong>Transit</strong> (data in motion).
                Each state receives independent Confidentiality / Integrity / Availability ratings per NIST SP 800-60.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Mode Toggle */}
              <div className="flex items-center gap-3">
                <Button
                  size="sm"
                  variant={fips199UseDefaults ? "default" : "outline"}
                  onClick={() => { setFips199UseDefaults(true); setFips199Custom(null); }}
                  className="text-xs"
                >
                  Industry Defaults
                </Button>
                <Button
                  size="sm"
                  variant={!fips199UseDefaults ? "default" : "outline"}
                  onClick={() => {
                    setFips199UseDefaults(false);
                    if (!fips199Custom && fips199DefaultsQ.data) {
                      setFips199Custom(fips199DefaultsQ.data.category as any);
                    } else if (!fips199Custom) {
                      setFips199Custom({
                        access:  { confidentiality: "moderate", integrity: "moderate", availability: "moderate" },
                        storage: { confidentiality: "moderate", integrity: "moderate", availability: "moderate" },
                        transit: { confidentiality: "moderate", integrity: "moderate", availability: "moderate" },
                      });
                    }
                  }}
                  className="text-xs"
                >
                  Custom Categorization
                </Button>
              </div>

              {/* Industry/Tier selectors (same as Industry tab) */}
              <div className="flex gap-4 items-end">
                <div className="flex-1">
                  <Label className="text-zinc-400 text-xs mb-1">Industry Vertical</Label>
                  <Select value={selectedIndustry} onValueChange={(v) => setSelectedIndustry(v as IndustryVertical)}>
                    <SelectTrigger className="bg-zinc-800 border-zinc-700">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="Corporate_Enterprise">Corporate / Enterprise</SelectItem>
                      <SelectItem value="Industrial_OT_Manufacturing">Industrial OT / Manufacturing</SelectItem>
                      <SelectItem value="Government_Federal_State">Government (Federal / State)</SelectItem>
                      <SelectItem value="Healthcare">Healthcare</SelectItem>
                      <SelectItem value="Financial_Services">Financial Services</SelectItem>
                      <SelectItem value="Energy_Utilities">Energy / Utilities</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="flex-1">
                  <Label className="text-zinc-400 text-xs mb-1">Asset Tier</Label>
                  <Select value={selectedTier} onValueChange={(v) => setSelectedTier(v as AssetTierType)}>
                    <SelectTrigger className="bg-zinc-800 border-zinc-700">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="Tier_1_Strategic">Tier 1 — Strategic</SelectItem>
                      <SelectItem value="Tier_2_Operational">Tier 2 — Operational</SelectItem>
                      <SelectItem value="Tier_3_Tactical">Tier 3 — Tactical</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              {/* Three-State FIPS 199 Matrix */}
              {(() => {
                const currentCat = fips199UseDefaults
                  ? fips199DefaultsQ.data?.category
                  : fips199Custom;
                if (!currentCat) return <div className="text-zinc-500 text-sm">Loading categorization...</div>;

                const states = [
                  { key: "access" as const, label: "Access (Data in Use)", icon: <Monitor className="w-4 h-4" />, desc: "Actively processed or accessed by users/systems" },
                  { key: "storage" as const, label: "Storage (Data at Rest)", icon: <HardDrive className="w-4 h-4" />, desc: "Stored in databases, file systems, backups, archives" },
                  { key: "transit" as const, label: "Transit (Data in Motion)", icon: <Wifi className="w-4 h-4" />, desc: "Network transfers, API calls, replication, sync" },
                ];
                const dimensions = ["confidentiality", "integrity", "availability"] as const;
                const levelColors: Record<string, string> = {
                  low: "bg-green-500/20 text-green-400 border-green-500/30",
                  moderate: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
                  high: "bg-red-500/20 text-red-400 border-red-500/30",
                };

                return (
                  <div className="space-y-3">
                    {states.map((state) => {
                      const stateData = (currentCat as any)[state.key];
                      return (
                        <div key={state.key} className="p-3 rounded-lg bg-zinc-800/40 border border-zinc-700/50">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="text-purple-400">{state.icon}</span>
                            <span className="text-sm font-semibold text-zinc-200">{state.label}</span>
                          </div>
                          <p className="text-[10px] text-zinc-500 mb-2">{state.desc}</p>
                          <div className="grid grid-cols-3 gap-2">
                            {dimensions.map((dim) => (
                              <div key={dim} className="space-y-1">
                                <Label className="text-[10px] text-zinc-500 capitalize">{dim}</Label>
                                {fips199UseDefaults ? (
                                  <Badge className={`w-full justify-center text-[10px] ${levelColors[stateData[dim]]}`}>
                                    {stateData[dim].toUpperCase()}
                                  </Badge>
                                ) : (
                                  <Select
                                    value={stateData[dim]}
                                    onValueChange={(v) => {
                                      setFips199Custom((prev) => {
                                        if (!prev) return prev;
                                        return {
                                          ...prev,
                                          [state.key]: { ...prev[state.key], [dim]: v },
                                        };
                                      });
                                    }}
                                  >
                                    <SelectTrigger className="h-7 text-[10px] bg-zinc-900 border-zinc-700">
                                      <SelectValue />
                                    </SelectTrigger>
                                    <SelectContent>
                                      <SelectItem value="low">LOW</SelectItem>
                                      <SelectItem value="moderate">MODERATE</SelectItem>
                                      <SelectItem value="high">HIGH</SelectItem>
                                    </SelectContent>
                                  </Select>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                );
              })()}

              {/* Compute Custom FIPS 199 Button */}
              {!fips199UseDefaults && fips199Custom && (
                <Button
                  size="sm"
                  onClick={() => computeFips199M.mutate(fips199Custom)}
                  disabled={computeFips199M.isPending}
                  className="bg-purple-600 hover:bg-purple-700"
                >
                  <RefreshCw className={`w-3 h-3 mr-1 ${computeFips199M.isPending ? "animate-spin" : ""}`} />
                  Compute Adjustments
                </Button>
              )}

              {/* FIPS 199 Results */}
              {(() => {
                const adj = fips199UseDefaults
                  ? fips199DefaultsQ.data?.adjustments
                  : computeFips199M.data?.adjustments;
                if (!adj) return null;

                const levelColors: Record<string, string> = {
                  low: "text-green-400",
                  moderate: "text-yellow-400",
                  high: "text-red-400",
                };

                return (
                  <div className="space-y-3 mt-4">
                    {/* High Watermark Summary */}
                    <div className="p-3 rounded-lg bg-gradient-to-r from-purple-500/5 to-cyan-500/5 border border-purple-500/20">
                      <h4 className="text-sm font-semibold text-zinc-300 mb-2">High Watermark (Aggregate)</h4>
                      <p className="text-[10px] text-zinc-500 mb-2">
                        Per FIPS PUB 199: The overall security category is the highest impact level across all information states.
                      </p>
                      <div className="grid grid-cols-4 gap-2">
                        <div className="text-center p-2 bg-zinc-900/60 rounded">
                          <div className="text-[10px] text-zinc-500">Confidentiality</div>
                          <div className={`text-sm font-semibold ${levelColors[adj.highWatermark.confidentiality]}`}>
                            {adj.highWatermark.confidentiality.toUpperCase()}
                          </div>
                        </div>
                        <div className="text-center p-2 bg-zinc-900/60 rounded">
                          <div className="text-[10px] text-zinc-500">Integrity</div>
                          <div className={`text-sm font-semibold ${levelColors[adj.highWatermark.integrity]}`}>
                            {adj.highWatermark.integrity.toUpperCase()}
                          </div>
                        </div>
                        <div className="text-center p-2 bg-zinc-900/60 rounded">
                          <div className="text-[10px] text-zinc-500">Availability</div>
                          <div className={`text-sm font-semibold ${levelColors[adj.highWatermark.availability]}`}>
                            {adj.highWatermark.availability.toUpperCase()}
                          </div>
                        </div>
                        <div className="text-center p-2 bg-zinc-900/60 rounded border border-purple-500/30">
                          <div className="text-[10px] text-zinc-500">Overall</div>
                          <div className={`text-sm font-bold ${levelColors[adj.highWatermark.overallLevel]}`}>
                            {adj.highWatermark.overallLevel.toUpperCase()}
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Per-State Impact */}
                    <div className="p-3 rounded-lg bg-zinc-800/40 border border-zinc-700/50">
                      <h4 className="text-sm font-semibold text-zinc-300 mb-2">Per-State Impact Levels</h4>
                      <div className="grid grid-cols-3 gap-2">
                        {(["access", "storage", "transit"] as const).map((state) => (
                          <div key={state} className="text-center p-2 bg-zinc-900/40 rounded">
                            <div className="text-[10px] text-zinc-500 capitalize">{state}</div>
                            <div className={`text-sm font-semibold ${levelColors[adj.stateImpacts[state]]}`}>
                              {adj.stateImpacts[state].toUpperCase()}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Score Adjustments */}
                    <div className="grid grid-cols-2 gap-3">
                      <div className="p-3 rounded-lg bg-zinc-800/40 border border-zinc-700/50">
                        <h4 className="text-xs font-semibold text-zinc-400 mb-2">CARVER Floor Adjustments</h4>
                        {Object.entries(adj.carverFloors).map(([key, val]) => (
                          <div key={key} className="flex justify-between text-xs py-0.5">
                            <span className="text-zinc-500 capitalize">{key}</span>
                            <span className="font-mono text-amber-400">≥ {String(val)}</span>
                          </div>
                        ))}
                      </div>
                      <div className="p-3 rounded-lg bg-zinc-800/40 border border-zinc-700/50">
                        <h4 className="text-xs font-semibold text-zinc-400 mb-2">SHOCK Floor Adjustments</h4>
                        {Object.entries(adj.shockFloors).map(([key, val]) => (
                          <div key={key} className="flex justify-between text-xs py-0.5">
                            <span className="text-zinc-500 capitalize">{key.replace(/([A-Z])/g, " $1").trim()}</span>
                            <span className="font-mono text-cyan-400">≥ {String(val)}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Mission Multiplier */}
                    <div className="p-3 rounded-lg bg-gradient-to-r from-purple-500/10 to-transparent border border-purple-500/20">
                      <div className="flex items-center justify-between">
                        <div>
                          <h4 className="text-sm font-semibold text-zinc-300">FIPS 199 Mission Multiplier</h4>
                          <p className="text-[10px] text-zinc-500 mt-0.5">
                            Applied as a scaling factor in the hybrid formula. Low=0.9x, Moderate=1.3x, High=1.8x
                          </p>
                        </div>
                        <div className="text-2xl font-bold font-mono text-purple-400">
                          {adj.missionMultiplier}x
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })()}
            </CardContent>
          </Card>
        </TabsContent>
        {/* CARVER Module Tab */}
        <TabsContent value="carver-module" className="space-y-4">
          <CarverModuleTab />
        </TabsContent>
      </Tabs>
    </div>
    </AppShell>
  );
}

/* ─── CARVER Module Tab Component ─────────────────────────────────── */
function CarverModuleTab() {
  const [selectedSector, setSelectedSector] = useState<string>("banking_financial_services");
  const [testDomain, setTestDomain] = useState("");
  const [showTrainingData, setShowTrainingData] = useState(false);

  const sectorProfiles = trpc.scoring.getSectorProfiles.useQuery();
  const carverPresets = trpc.scoring.getCarverPresets.useQuery();
  const threatLikelihood = trpc.scoring.getThreatLikelihood.useQuery();
  const buildRiskCardMutation = trpc.scoring.buildRiskCard.useMutation();
  const inferResult = trpc.scoring.inferSectorFromDomain.useQuery(
    { domain: testDomain, keywords: [] },
    { enabled: testDomain.length > 3 }
  );
  const [riskCardData, setRiskCardData] = useState<any>(null);

  const handleScanDomain = () => {
    if (testDomain.length > 3) {
      buildRiskCardMutation.mutate(
        { assetId: testDomain, assetLabel: testDomain, domain: testDomain, keywords: [] },
        { onSuccess: (data) => setRiskCardData(data) }
      );
    }
  };

  const sectorList = [
    { key: "banking_financial_services", label: "Banking & Financial Services" },
    { key: "healthcare_providers", label: "Healthcare & Life Sciences" },
    { key: "defense_aerospace", label: "Defense & Aerospace" },
    { key: "federal_government", label: "Government (Federal/State/Local)" },
    { key: "electric_gas_utilities", label: "Energy & Utilities" },
    { key: "saas_tech", label: "Technology / SaaS" },
  ];

  const currentPreset = carverPresets.data?.[selectedSector];
  const currentThreats = threatLikelihood.data?.[selectedSector];
  const currentProfile = sectorProfiles.data?.find((p: any) => p.sector === selectedSector);

  return (
    <div className="space-y-4">
      {/* Header */}
      <Card className="bg-zinc-900/60 border-zinc-800">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-lg flex items-center gap-2">
                <Crosshair className="w-5 h-5 text-red-400" />
                Auto-Industry CARVER Module
              </CardTitle>
              <CardDescription className="text-zinc-400 mt-1">
                Industry-aware CARVER+SHOCK presets with NAICS inference, regulatory overlays,
                threat actor likelihood, and Caldera operation prioritization.
                Trained on 124 domains across 18 sectors.
              </CardDescription>
            </div>
            <Badge variant="outline" className="border-red-500/30 text-red-400">
              v2.0 — NAICS + FedRAMP + Explainable
            </Badge>
          </div>
        </CardHeader>
      </Card>

      {/* Domain Inference Tester */}
      <Card className="bg-zinc-900/60 border-zinc-800">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm flex items-center gap-2">
            <Globe className="w-4 h-4 text-blue-400" />
            Domain Intelligence Scanner
          </CardTitle>
          <CardDescription className="text-xs text-zinc-500">
            Enter a domain to run NAICS inference, sector classification, and generate an explainable risk card
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex gap-2 mb-4">
            <Input
              placeholder="e.g., jpmorganchase.com"
              value={testDomain}
              onChange={(e) => setTestDomain(e.target.value)}
              className="bg-zinc-800/50 border-zinc-700 text-sm"
            />
            <Button
              variant="outline"
              size="sm"
              onClick={handleScanDomain}
              disabled={testDomain.length <= 3 || buildRiskCardMutation.isPending}
              className="border-red-500/30 text-red-400 hover:bg-red-500/10"
            >
              {buildRiskCardMutation.isPending ? <RefreshCw className="w-3 h-3 mr-1 animate-spin" /> : <Target className="w-3 h-3 mr-1" />}
              Scan
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => { setTestDomain(""); setRiskCardData(null); }}
              className="border-zinc-700"
            >
              <RotateCcw className="w-3 h-3 mr-1" /> Clear
            </Button>
          </div>

          {inferResult.data && testDomain.length > 3 && (
            <div className="space-y-3">
              {/* Sector Inference */}
              <div className="grid grid-cols-3 gap-3">
                <div className="p-3 rounded-lg bg-blue-500/10 border border-blue-500/20">
                  <p className="text-[10px] text-zinc-500 uppercase tracking-wider">Inferred Sector</p>
                  <p className="text-sm font-semibold text-blue-400 mt-1">
                    {inferResult.data.sector.replace(/_/g, ' ').replace(/\b\w/g, (c: string) => c.toUpperCase())}
                  </p>
                  <p className="text-[10px] text-zinc-500 mt-0.5">
                    Confidence: {(inferResult.data.confidence * 100).toFixed(0)}%
                  </p>
                </div>
                <div className="p-3 rounded-lg bg-purple-500/10 border border-purple-500/20">
                  <p className="text-[10px] text-zinc-500 uppercase tracking-wider">Regulatory Profile</p>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {inferResult.data.regulatoryProfile?.map((r: string) => (
                      <Badge key={r} variant="outline" className="text-[10px] border-purple-500/30 text-purple-400">{r}</Badge>
                    )) || <span className="text-xs text-zinc-500">None detected</span>}
                  </div>
                </div>
                <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/20">
                  <p className="text-[10px] text-zinc-500 uppercase tracking-wider">NAICS Code</p>
                  <p className="text-sm font-semibold text-amber-400 mt-1">
                    {inferResult.data.naics?.primaryNaics || 'N/A'}
                  </p>
                  <p className="text-[10px] text-zinc-500 mt-0.5">
                    {inferResult.data.naics?.primaryLabel || 'Unknown'}
                  </p>
                </div>
              </div>
            </div>
          )}

          {riskCardData && testDomain.length > 3 && (
            <div className="mt-4 space-y-3">
              {/* Risk Card Scores */}
              <div className="grid grid-cols-4 gap-2">
                <div className="p-2 rounded bg-red-500/10 border border-red-500/20 text-center">
                  <p className="text-[10px] text-zinc-500">Hybrid Score</p>
                  <p className="text-xl font-bold font-mono text-red-400">{riskCardData.scores.hybrid.toFixed(1)}</p>
                </div>
                <div className="p-2 rounded bg-orange-500/10 border border-orange-500/20 text-center">
                  <p className="text-[10px] text-zinc-500">CARVER+SHOCK</p>
                  <p className="text-xl font-bold font-mono text-orange-400">{riskCardData.scores.carverShock.toFixed(1)}</p>
                </div>
                <div className="p-2 rounded bg-yellow-500/10 border border-yellow-500/20 text-center">
                  <p className="text-[10px] text-zinc-500">CVSS Base</p>
                  <p className="text-xl font-bold font-mono text-yellow-400">{riskCardData.scores.cvss?.base?.toFixed(1) || '0.0'}</p>
                </div>
                <div className="p-2 rounded bg-emerald-500/10 border border-emerald-500/20 text-center">
                  <p className="text-[10px] text-zinc-500">Priority Tier</p>
                  <p className={`text-xl font-bold font-mono ${
                    riskCardData.scores.priorityTier === 'P0' ? 'text-red-400' :
                    riskCardData.scores.priorityTier === 'P1' ? 'text-orange-400' :
                    riskCardData.scores.priorityTier === 'P2' ? 'text-yellow-400' : 'text-emerald-400'
                  }`}>{riskCardData.scores.priorityTier}</p>
                </div>
              </div>

              {/* Top Drivers */}
              <div className="p-3 rounded-lg bg-zinc-800/50 border border-zinc-700/50">
                <h4 className="text-xs font-semibold text-zinc-400 mb-2 flex items-center gap-1">
                  <TrendingUp className="w-3 h-3" /> Top Risk Drivers
                </h4>
                <div className="space-y-1">
                  {riskCardData.topDrivers?.map((d: any, i: number) => (
                    <div key={i} className="text-xs">
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className={`text-[9px] ${
                          d.impact === 'increase' ? 'border-red-500/30 text-red-400' : 'border-emerald-500/30 text-emerald-400'
                        }`}>{d.impact === 'increase' ? '↑' : '↓'}</Badge>
                        <span className="text-zinc-300 font-medium">{d.driver}</span>
                      </div>
                      {d.evidence?.map((e: string, j: number) => (
                        <p key={j} className="text-zinc-500 ml-8 text-[10px]">{e}</p>
                      ))}
                    </div>
                  ))}
                </div>
              </div>

              {/* Recommended Actions */}
              <div className="p-3 rounded-lg bg-zinc-800/50 border border-zinc-700/50">
                <h4 className="text-xs font-semibold text-zinc-400 mb-2 flex items-center gap-1">
                  <Shield className="w-3 h-3" /> Recommended Actions
                </h4>
                <div className="space-y-1">
                  {riskCardData.recommendedActions?.slice(0, 5).map((a: string, i: number) => (
                    <div key={i} className="flex items-start gap-2 text-xs">
                      <span className="text-emerald-400 mt-0.5">→</span>
                      <span className="text-zinc-300">{a}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Caldera Priority */}
              {riskCardData.calderaPriority && (
                <div className="p-3 rounded-lg bg-red-500/5 border border-red-500/20">
                  <h4 className="text-xs font-semibold text-zinc-400 mb-2 flex items-center gap-1">
                    <Target className="w-3 h-3 text-red-400" /> Caldera Operation Priority
                  </h4>
                  <div className="grid grid-cols-3 gap-2 text-xs">
                    <div>
                      <p className="text-zinc-500">Op Tier</p>
                      <p className="font-semibold text-red-400">{riskCardData.calderaPriority.operationTier}</p>
                    </div>
                    <div>
                      <p className="text-zinc-500">Profile</p>
                      <p className="font-semibold text-zinc-300">{riskCardData.calderaPriority.operationProfile}</p>
                    </div>
                    <div>
                      <p className="text-zinc-500">Adversaries</p>
                      <div className="flex flex-wrap gap-1 mt-0.5">
                        {riskCardData.calderaPriority.recommendedAdversaries?.slice(0, 3).map((a: string) => (
                          <Badge key={a} variant="outline" className="text-[9px] border-red-500/30 text-red-300">{a}</Badge>
                        ))}
                      </div>
                    </div>
                  </div>
                  {riskCardData.calderaPriority.objectives?.length > 0 && (
                    <div className="mt-2">
                      <p className="text-zinc-500 text-[10px] mb-1">Objectives</p>
                      <div className="flex flex-wrap gap-1">
                        {riskCardData.calderaPriority.objectives.map((o: string) => (
                          <Badge key={o} variant="outline" className="text-[9px] border-zinc-600 text-zinc-400">{o}</Badge>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Sector CARVER Presets */}
      <Card className="bg-zinc-900/60 border-zinc-800">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm flex items-center gap-2">
              <Layers className="w-4 h-4 text-orange-400" />
              Sector CARVER+SHOCK Presets
            </CardTitle>
            <Select value={selectedSector} onValueChange={setSelectedSector}>
              <SelectTrigger className="w-64 bg-zinc-800/50 border-zinc-700 text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {sectorList.map(s => (
                  <SelectItem key={s.key} value={s.key}>{s.label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </CardHeader>
        <CardContent>
          {currentPreset && (() => {
            const carverDims = ['criticality', 'accessibility', 'recuperability', 'vulnerability', 'effect', 'recognizability'];
            const shockDim = 'shock';
            const sectorReg = currentProfile?.regulatory || [];
            return (
              <div className="space-y-4">
                {/* CARVER Scores Grid */}
                <div>
                  <h4 className="text-xs font-semibold text-zinc-400 mb-2">CARVER Dimensions</h4>
                  <div className="grid grid-cols-6 gap-2">
                    {carverDims.map(dim => (
                      <div key={dim} className="p-2 rounded bg-zinc-800/50 border border-zinc-700/50 text-center">
                        <p className="text-[10px] text-zinc-500 uppercase">{dim.slice(0, 5)}</p>
                        <p className="text-lg font-bold font-mono text-orange-400">{(currentPreset as any)[dim] ?? '-'}</p>
                      </div>
                    ))}
                  </div>
                </div>

                {/* SHOCK Score */}
                <div>
                  <h4 className="text-xs font-semibold text-zinc-400 mb-2">SHOCK Score</h4>
                  <div className="grid grid-cols-1 gap-2 max-w-[120px]">
                    <div className="p-2 rounded bg-zinc-800/50 border border-zinc-700/50 text-center">
                      <p className="text-[10px] text-zinc-500 uppercase">SHOCK</p>
                      <p className="text-lg font-bold font-mono text-amber-400">{(currentPreset as any)[shockDim] ?? '-'}</p>
                    </div>
                  </div>
                </div>

                {/* Regulatory Overlays */}
                {sectorReg.length > 0 && (
                  <div>
                    <h4 className="text-xs font-semibold text-zinc-400 mb-2">Regulatory Overlays</h4>
                    <div className="flex flex-wrap gap-2">
                      {sectorReg.map((r: string) => (
                        <Badge key={r} variant="outline" className="border-purple-500/30 text-purple-400">{r}</Badge>
                      ))}
                    </div>
                  </div>
                )}

                {/* Sector Multiplier */}
                <div className="p-3 rounded-lg bg-gradient-to-r from-red-500/10 to-transparent border border-red-500/20">
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="text-sm font-semibold text-zinc-300">Sector Criticality Multiplier</h4>
                      <p className="text-[10px] text-zinc-500 mt-0.5">
                        Applied to hybrid fusion formula: CARVER composite × sector_multiplier + CVSS×0.6 + Exploitability×0.4
                      </p>
                    </div>
                    <div className="text-2xl font-bold font-mono text-red-400">
                      {selectedSector === 'defense_aerospace' ? '1.3' :
                       selectedSector === 'electric_gas_utilities' ? '1.25' :
                       selectedSector === 'federal_government' ? '1.2' :
                       selectedSector === 'banking_financial_services' ? '1.15' :
                       selectedSector === 'healthcare_providers' ? '1.1' : '1.0'}x
                    </div>
                  </div>
                </div>
              </div>
            );
          })()}
        </CardContent>
      </Card>

      {/* Threat Actor Likelihood */}
      <Card className="bg-zinc-900/60 border-zinc-800">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-yellow-400" />
            Threat Actor Likelihood by Sector
          </CardTitle>
        </CardHeader>
        <CardContent>
          {currentThreats && (
            <div className="space-y-2">
              {Object.entries(currentThreats).sort(([,a]: any, [,b]: any) => b - a).map(([actor, weight]: [string, any]) => (
                <div key={actor} className="flex items-center gap-3">
                  <span className="text-xs text-zinc-400 w-40 truncate">
                    {actor.replace(/_/g, ' ').replace(/\b\w/g, (c: string) => c.toUpperCase())}
                  </span>
                  <div className="flex-1 h-2 bg-zinc-800 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all ${
                        weight > 0.7 ? 'bg-red-500' : weight > 0.4 ? 'bg-orange-500' : weight > 0.2 ? 'bg-yellow-500' : 'bg-zinc-600'
                      }`}
                      style={{ width: `${weight * 100}%` }}
                    />
                  </div>
                  <span className="text-xs font-mono text-zinc-500 w-12 text-right">{(weight * 100).toFixed(0)}%</span>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Training Data Summary */}
      <Card className="bg-zinc-900/60 border-zinc-800">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm flex items-center gap-2">
              <Brain className="w-4 h-4 text-emerald-400" />
              LLM Training Dataset
            </CardTitle>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setShowTrainingData(!showTrainingData)}
              className="border-zinc-700 text-xs"
            >
              {showTrainingData ? <ChevronUp className="w-3 h-3 mr-1" /> : <ChevronDown className="w-3 h-3 mr-1" />}
              {showTrainingData ? 'Hide' : 'Show'} Details
            </Button>
          </div>
          <CardDescription className="text-xs text-zinc-500">
            124 domains × 18 sectors processed for scoring baseline calibration
          </CardDescription>
        </CardHeader>
        {showTrainingData && (
          <CardContent>
            <div className="grid grid-cols-2 gap-3">
              <div className="p-3 rounded-lg bg-zinc-800/50 border border-zinc-700/50">
                <h4 className="text-xs font-semibold text-zinc-400 mb-2">Training Modules</h4>
                <div className="space-y-1 text-xs">
                  <div className="flex justify-between"><span className="text-zinc-400">Sector Classification</span><Badge variant="outline" className="text-[9px]">124 pairs</Badge></div>
                  <div className="flex justify-between"><span className="text-zinc-400">NAICS Inference</span><Badge variant="outline" className="text-[9px]">124 pairs</Badge></div>
                  <div className="flex justify-between"><span className="text-zinc-400">Scoring Calibration</span><Badge variant="outline" className="text-[9px]">124 pairs</Badge></div>
                  <div className="flex justify-between"><span className="text-zinc-400">Sector Baselines</span><Badge variant="outline" className="text-[9px]">18 sectors</Badge></div>
                  <div className="flex justify-between"><span className="text-zinc-400">Threat Likelihood</span><Badge variant="outline" className="text-[9px]">18 sectors</Badge></div>
                  <div className="flex justify-between"><span className="text-zinc-400">Caldera Operations</span><Badge variant="outline" className="text-[9px]">124 pairs</Badge></div>
                  <div className="flex justify-between"><span className="text-zinc-400">Prompt-Response Pairs</span><Badge variant="outline" className="text-[9px]">124 pairs</Badge></div>
                </div>
              </div>
              <div className="p-3 rounded-lg bg-zinc-800/50 border border-zinc-700/50">
                <h4 className="text-xs font-semibold text-zinc-400 mb-2">Scoring Baselines</h4>
                <div className="space-y-1 text-xs">
                  <div className="flex justify-between"><span className="text-zinc-400">Defense/Aerospace</span><span className="font-mono text-red-400">9.66 avg</span></div>
                  <div className="flex justify-between"><span className="text-zinc-400">Banking/Financial</span><span className="font-mono text-orange-400">9.04 avg</span></div>
                  <div className="flex justify-between"><span className="text-zinc-400">Government</span><span className="font-mono text-yellow-400">8.75 avg</span></div>
                  <div className="flex justify-between"><span className="text-zinc-400">Chemical/Industrial</span><span className="font-mono text-yellow-400">8.39 avg</span></div>
                  <div className="flex justify-between"><span className="text-zinc-400">Healthcare</span><span className="font-mono text-emerald-400">7.27 avg</span></div>
                  <div className="flex justify-between"><span className="text-zinc-400">Energy/Utilities</span><span className="font-mono text-emerald-400">7.14 avg</span></div>
                  <div className="flex justify-between"><span className="text-zinc-400">Technology/SaaS</span><span className="font-mono text-blue-400">7.14 avg</span></div>
                </div>
              </div>
            </div>
          </CardContent>
        )}
      </Card>
    </div>
  );
}
