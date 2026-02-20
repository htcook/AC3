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
  Building2, Layers, Cpu, Network, FileSearch,
} from "lucide-react";

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
  const [selectedScanId, setSelectedScanId] = useState<number | undefined>();
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [showSimulator, setShowSimulator] = useState(false);

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
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-zinc-100 flex items-center gap-2">
            <Crosshair className="w-6 h-6 text-cyan-400" />
            Adaptive Risk Scoring Engine
          </h1>
          <p className="text-sm text-zinc-400 mt-1">
            Mission-aware hybrid scoring with dynamic re-assessment during discovery
          </p>
        </div>
        <div className="flex gap-2">
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
          <TabsTrigger value="audit">
            <Eye className="w-4 h-4 mr-1" /> Audit Log
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
      </Tabs>
    </div>
  );
}
