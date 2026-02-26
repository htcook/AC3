/**
 * Graph Compare Page
 *
 * Side-by-side comparison of two ability graphs showing:
 * - Technique overlap / divergence
 * - Tactic coverage heatmap
 * - Similarity metrics (Jaccard, Dice, Overlap)
 * - Safety tier distribution
 * - Structural metrics
 */
import { useState, useMemo } from "react";
import { useLocation } from "wouter";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";
import {
  GitBranch,
  ArrowLeftRight,
  Target,
  Shield,
  Network,
  ArrowRight,
  Layers,
  BarChart3,
  CheckCircle2,
  XCircle,
  Minus,
  ChevronLeft,
} from "lucide-react";

// ─── Tactic colors (shared with AbilityGraph) ──────────────────────────

const TACTIC_COLORS: Record<string, string> = {
  "reconnaissance": "#60a5fa",
  "resource-development": "#818cf8",
  "initial-access": "#f472b6",
  "execution": "#fb923c",
  "persistence": "#a78bfa",
  "privilege-escalation": "#e879f9",
  "defense-evasion": "#34d399",
  "credential-access": "#fbbf24",
  "discovery": "#22d3ee",
  "lateral-movement": "#f87171",
  "collection": "#c084fc",
  "command-and-control": "#94a3b8",
  "exfiltration": "#ef4444",
  "impact": "#dc2626",
};

const SAFETY_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  passive: { bg: "bg-emerald-500/10", text: "text-emerald-400", border: "border-emerald-500/30" },
  low_impact: { bg: "bg-blue-500/10", text: "text-blue-400", border: "border-blue-500/30" },
  medium_impact: { bg: "bg-amber-500/10", text: "text-amber-400", border: "border-amber-500/30" },
  high_impact: { bg: "bg-orange-500/10", text: "text-orange-400", border: "border-orange-500/30" },
  critical_impact: { bg: "bg-red-500/10", text: "text-red-400", border: "border-red-500/30" },
};

const TACTIC_ORDER: Record<string, number> = {
  "reconnaissance": 0, "resource-development": 1, "initial-access": 2,
  "execution": 3, "persistence": 4, "privilege-escalation": 5,
  "defense-evasion": 6, "credential-access": 7, "discovery": 8,
  "lateral-movement": 9, "collection": 10, "command-and-control": 11,
  "exfiltration": 12, "impact": 13,
};

// ─── Similarity Gauge ───────────────────────────────────────────────────

function SimilarityGauge({ value, label, size = 120 }: { value: number; label: string; size?: number }) {
  const pct = Math.round(value * 100);
  const radius = (size - 16) / 2;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference * (1 - value);

  let color = "#ef4444"; // red
  if (pct > 60) color = "#22c55e"; // green
  else if (pct > 30) color = "#f59e0b"; // amber
  else if (pct > 10) color = "#f97316"; // orange

  return (
    <div className="flex flex-col items-center gap-1">
      <svg width={size} height={size} className="transform -rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth="4"
          className="text-muted/20"
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth="4"
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          className="transition-all duration-1000"
        />
        <text
          x={size / 2}
          y={size / 2}
          textAnchor="middle"
          dominantBaseline="central"
          className="fill-foreground text-lg font-bold"
          transform={`rotate(90, ${size / 2}, ${size / 2})`}
        >
          {pct}%
        </text>
      </svg>
      <span className="text-xs text-muted-foreground">{label}</span>
    </div>
  );
}

// ─── Tactic Coverage Bar ────────────────────────────────────────────────

function TacticCoverageBar({
  coverage,
}: {
  coverage: Array<{
    tactic: string;
    countA: number;
    countB: number;
    shared: string[];
  }>;
}) {
  const maxCount = Math.max(...coverage.flatMap(c => [c.countA, c.countB]), 1);

  return (
    <div className="space-y-2">
      {coverage
        .sort((a, b) => (TACTIC_ORDER[a.tactic] ?? 99) - (TACTIC_ORDER[b.tactic] ?? 99))
        .map((c) => {
          const color = TACTIC_COLORS[c.tactic] || "#94a3b8";
          return (
            <div key={c.tactic} className="group">
              <div className="flex items-center justify-between text-xs mb-1">
                <span className="font-medium capitalize" style={{ color }}>
                  {c.tactic.replace(/-/g, " ")}
                </span>
                <span className="text-muted-foreground">
                  {c.shared.length > 0 && (
                    <span className="text-emerald-400 mr-2">{c.shared.length} shared</span>
                  )}
                  {c.countA} / {c.countB}
                </span>
              </div>
              <div className="flex gap-1 h-4">
                {/* Graph A bar */}
                <div className="flex-1 bg-muted/20 rounded-l overflow-hidden">
                  <div
                    className="h-full rounded-l transition-all duration-500"
                    style={{
                      width: `${(c.countA / maxCount) * 100}%`,
                      backgroundColor: `${color}80`,
                    }}
                  />
                </div>
                {/* Graph B bar */}
                <div className="flex-1 bg-muted/20 rounded-r overflow-hidden flex justify-end">
                  <div
                    className="h-full rounded-r transition-all duration-500"
                    style={{
                      width: `${(c.countB / maxCount) * 100}%`,
                      backgroundColor: `${color}40`,
                      borderLeft: c.shared.length > 0 ? `2px solid ${color}` : "none",
                    }}
                  />
                </div>
              </div>
            </div>
          );
        })}
    </div>
  );
}

// ─── Technique Overlap Table ────────────────────────────────────────────

function TechniqueOverlapTable({
  techniques,
  nameA,
  nameB,
}: {
  techniques: Array<{
    techniqueId: string;
    techniqueName: string;
    tactic: string;
    inA: boolean;
    inB: boolean;
    safetyTierA?: string;
    safetyTierB?: string;
  }>;
  nameA: string;
  nameB: string;
}) {
  const [filter, setFilter] = useState<"all" | "shared" | "unique-a" | "unique-b">("all");

  const filtered = useMemo(() => {
    switch (filter) {
      case "shared":
        return techniques.filter(t => t.inA && t.inB);
      case "unique-a":
        return techniques.filter(t => t.inA && !t.inB);
      case "unique-b":
        return techniques.filter(t => !t.inA && t.inB);
      default:
        return techniques;
    }
  }, [techniques, filter]);

  return (
    <div className="space-y-3">
      <div className="flex gap-2">
        {[
          { key: "all", label: "All", count: techniques.length },
          { key: "shared", label: "Shared", count: techniques.filter(t => t.inA && t.inB).length },
          { key: "unique-a", label: `Only ${nameA.split(" ")[0]}`, count: techniques.filter(t => t.inA && !t.inB).length },
          { key: "unique-b", label: `Only ${nameB.split(" ")[0]}`, count: techniques.filter(t => !t.inA && t.inB).length },
        ].map((f) => (
          <Button
            key={f.key}
            variant={filter === f.key ? "default" : "outline"}
            size="sm"
            className="text-xs gap-1"
            onClick={() => setFilter(f.key as any)}
          >
            {f.label}
            <Badge variant="secondary" className="ml-1 text-[10px] px-1.5">
              {f.count}
            </Badge>
          </Button>
        ))}
      </div>

      <div className="border border-border/30 rounded-lg overflow-hidden">
        <table className="w-full text-xs">
          <thead>
            <tr className="bg-muted/20 border-b border-border/30">
              <th className="text-left px-3 py-2 font-medium">Technique</th>
              <th className="text-left px-3 py-2 font-medium">Tactic</th>
              <th className="text-center px-3 py-2 font-medium w-20">{nameA.split(" — ")[0].slice(0, 12)}</th>
              <th className="text-center px-3 py-2 font-medium w-20">{nameB.split(" — ")[0].slice(0, 12)}</th>
            </tr>
          </thead>
          <tbody>
            {filtered.slice(0, 50).map((t) => (
              <tr key={t.techniqueId} className="border-b border-border/10 hover:bg-muted/10">
                <td className="px-3 py-1.5">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-muted-foreground">{t.techniqueId}</span>
                    <span>{t.techniqueName}</span>
                  </div>
                </td>
                <td className="px-3 py-1.5">
                  <span
                    className="capitalize"
                    style={{ color: TACTIC_COLORS[t.tactic] || "#94a3b8" }}
                  >
                    {t.tactic.replace(/-/g, " ")}
                  </span>
                </td>
                <td className="text-center px-3 py-1.5">
                  {t.inA ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 mx-auto" />
                  ) : (
                    <Minus className="w-4 h-4 text-muted-foreground/30 mx-auto" />
                  )}
                </td>
                <td className="text-center px-3 py-1.5">
                  {t.inB ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 mx-auto" />
                  ) : (
                    <Minus className="w-4 h-4 text-muted-foreground/30 mx-auto" />
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {filtered.length > 50 && (
          <div className="text-center py-2 text-xs text-muted-foreground bg-muted/10">
            Showing 50 of {filtered.length} techniques
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Safety Distribution Chart ──────────────────────────────────────────

function SafetyDistributionChart({
  distA,
  distB,
  nameA,
  nameB,
}: {
  distA: Record<string, number>;
  distB: Record<string, number>;
  nameA: string;
  nameB: string;
}) {
  const tiers = ["passive", "low_impact", "medium_impact", "high_impact", "critical_impact"];
  const maxVal = Math.max(
    ...tiers.flatMap(t => [distA[t] || 0, distB[t] || 0]),
    1,
  );

  return (
    <div className="space-y-3">
      {tiers.map((tier) => {
        const style = SAFETY_COLORS[tier] || SAFETY_COLORS.medium_impact;
        const valA = distA[tier] || 0;
        const valB = distB[tier] || 0;
        return (
          <div key={tier}>
            <div className="flex items-center justify-between text-xs mb-1">
              <span className={`capitalize font-medium ${style.text}`}>
                {tier.replace("_", " ")}
              </span>
              <span className="text-muted-foreground">{valA} / {valB}</span>
            </div>
            <div className="flex gap-1 h-5">
              <div className="flex-1 bg-muted/20 rounded-l overflow-hidden">
                <div
                  className={`h-full rounded-l ${style.bg} transition-all duration-500`}
                  style={{ width: `${(valA / maxVal) * 100}%` }}
                />
              </div>
              <div className="flex-1 bg-muted/20 rounded-r overflow-hidden flex justify-end">
                <div
                  className={`h-full rounded-r ${style.bg} opacity-50 transition-all duration-500`}
                  style={{ width: `${(valB / maxVal) * 100}%` }}
                />
              </div>
            </div>
          </div>
        );
      })}
      <div className="flex items-center justify-center gap-6 text-xs text-muted-foreground pt-2">
        <span className="flex items-center gap-1.5">
          <span className="w-3 h-3 rounded bg-primary/40" /> {nameA.split(" — ")[0].slice(0, 15)}
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-3 h-3 rounded bg-primary/20" /> {nameB.split(" — ")[0].slice(0, 15)}
        </span>
      </div>
    </div>
  );
}

// ─── Main Component ─────────────────────────────────────────────────────

export default function GraphCompare() {
  const [, navigate] = useLocation();
  const [graphIdA, setGraphIdA] = useState<string>("");
  const [graphIdB, setGraphIdB] = useState<string>("");

  // Fetch graph list for selection
  const graphList = trpc.abilityGraph.list.useQuery({ limit: 100 });

  // Fetch comparison when both graphs are selected
  const comparison = trpc.abilityGraph.compare.useQuery(
    { graphIdA, graphIdB },
    { enabled: !!graphIdA && !!graphIdB && graphIdA !== graphIdB },
  );

  const graphs = graphList.data?.items || [];

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Button variant="ghost" size="sm" onClick={() => navigate("/ability-graph")}>
            <ChevronLeft className="w-4 h-4 mr-1" />
            Back
          </Button>
          <div>
            <h1 className="text-xl font-bold flex items-center gap-2">
              <ArrowLeftRight className="w-5 h-5 text-primary" />
              Graph Comparison
            </h1>
            <p className="text-sm text-muted-foreground mt-0.5">
              Compare technique overlap, tactic coverage, and structural differences between two ability graphs
            </p>
          </div>
        </div>
      </div>

      {/* Graph Selection */}
      <Card className="border-border/30 bg-card/50">
        <CardContent className="p-4">
          <div className="grid grid-cols-[1fr_auto_1fr] gap-4 items-end">
            <div className="space-y-2">
              <label className="text-xs font-medium text-muted-foreground">Graph A</label>
              <Select value={graphIdA} onValueChange={setGraphIdA}>
                <SelectTrigger>
                  <SelectValue placeholder="Select first graph…" />
                </SelectTrigger>
                <SelectContent>
                  {graphs
                    .filter(g => g.id !== graphIdB)
                    .map(g => (
                      <SelectItem key={g.id} value={g.id}>
                        <span className="flex items-center gap-2">
                          <GitBranch className="w-3.5 h-3.5 text-primary" />
                          {g.name}
                          {g.actorName && (
                            <span className="text-muted-foreground text-xs">({g.actorName})</span>
                          )}
                        </span>
                      </SelectItem>
                    ))}
                </SelectContent>
              </Select>
            </div>

            <div className="flex items-center justify-center pb-1">
              <ArrowLeftRight className="w-5 h-5 text-muted-foreground" />
            </div>

            <div className="space-y-2">
              <label className="text-xs font-medium text-muted-foreground">Graph B</label>
              <Select value={graphIdB} onValueChange={setGraphIdB}>
                <SelectTrigger>
                  <SelectValue placeholder="Select second graph…" />
                </SelectTrigger>
                <SelectContent>
                  {graphs
                    .filter(g => g.id !== graphIdA)
                    .map(g => (
                      <SelectItem key={g.id} value={g.id}>
                        <span className="flex items-center gap-2">
                          <GitBranch className="w-3.5 h-3.5 text-primary" />
                          {g.name}
                          {g.actorName && (
                            <span className="text-muted-foreground text-xs">({g.actorName})</span>
                          )}
                        </span>
                      </SelectItem>
                    ))}
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* No selection state */}
      {(!graphIdA || !graphIdB) && (
        <Card className="border-border/30 bg-card/50">
          <CardContent className="p-12 text-center">
            <ArrowLeftRight className="w-12 h-12 mx-auto mb-3 text-muted-foreground/30" />
            <h3 className="text-lg font-semibold mb-1">Select Two Graphs to Compare</h3>
            <p className="text-sm text-muted-foreground">
              Choose two ability graphs from the dropdowns above to see their technique overlap,
              tactic coverage differences, and structural comparison.
            </p>
          </CardContent>
        </Card>
      )}

      {/* Loading */}
      {graphIdA && graphIdB && comparison.isLoading && (
        <div className="text-center py-12 text-muted-foreground">
          Comparing graphs…
        </div>
      )}

      {/* Error */}
      {comparison.error && (
        <Card className="border-red-500/30 bg-red-500/5">
          <CardContent className="p-4 text-red-400 text-sm">
            {comparison.error.message}
          </CardContent>
        </Card>
      )}

      {/* Comparison Results */}
      {comparison.data && (
        <div className="space-y-6">
          {/* Summary */}
          <Card className="border-border/30 bg-card/50">
            <CardContent className="p-4">
              <p className="text-sm text-muted-foreground leading-relaxed">
                {comparison.data.summary}
              </p>
            </CardContent>
          </Card>

          {/* Similarity Metrics */}
          <div className="grid grid-cols-3 gap-4">
            <Card className="border-border/30 bg-card/50">
              <CardContent className="p-6 flex justify-center">
                <SimilarityGauge value={comparison.data.jaccardSimilarity} label="Jaccard Similarity" />
              </CardContent>
            </Card>
            <Card className="border-border/30 bg-card/50">
              <CardContent className="p-6 flex justify-center">
                <SimilarityGauge value={comparison.data.diceCoefficient} label="Dice Coefficient" />
              </CardContent>
            </Card>
            <Card className="border-border/30 bg-card/50">
              <CardContent className="p-6 flex justify-center">
                <SimilarityGauge value={comparison.data.overlapCoefficient} label="Overlap Coefficient" />
              </CardContent>
            </Card>
          </div>

          {/* Side-by-side stats */}
          <div className="grid grid-cols-2 gap-4">
            {[
              { data: comparison.data.graphA, label: "A" },
              { data: comparison.data.graphB, label: "B" },
            ].map(({ data: g, label }) => {
              const safetyStyle = SAFETY_COLORS[g.safetyTier] || SAFETY_COLORS.medium_impact;
              return (
                <Card key={label} className="border-border/30 bg-card/50">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center gap-2">
                      <Badge variant="outline" className="text-xs">{label}</Badge>
                      {g.name}
                    </CardTitle>
                    {g.actorName && (
                      <CardDescription className="text-xs">{g.actorName}</CardDescription>
                    )}
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div className="grid grid-cols-3 gap-2 text-xs">
                      <div className="text-center p-2 bg-muted/10 rounded">
                        <div className="text-muted-foreground flex items-center justify-center gap-1">
                          <Network className="w-3 h-3" /> Nodes
                        </div>
                        <div className="font-semibold text-sm">{g.nodeCount}</div>
                      </div>
                      <div className="text-center p-2 bg-muted/10 rounded">
                        <div className="text-muted-foreground flex items-center justify-center gap-1">
                          <ArrowRight className="w-3 h-3" /> Edges
                        </div>
                        <div className="font-semibold text-sm">{g.edgeCount}</div>
                      </div>
                      <div className="text-center p-2 bg-muted/10 rounded">
                        <div className="text-muted-foreground flex items-center justify-center gap-1">
                          <Layers className="w-3 h-3" /> Tactics
                        </div>
                        <div className="font-semibold text-sm">{g.tactics.length}</div>
                      </div>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <Badge variant="outline" className={`text-xs ${safetyStyle.text} ${safetyStyle.border}`}>
                        <Shield className="w-3 h-3 mr-1" />
                        {g.safetyTier.replace("_", " ")}
                      </Badge>
                    </div>
                    <div className="flex flex-wrap gap-1">
                      {g.tactics.map((t: string) => (
                        <span
                          key={t}
                          className="text-[10px] px-1.5 py-0.5 rounded-full capitalize"
                          style={{
                            backgroundColor: `${TACTIC_COLORS[t] || "#94a3b8"}15`,
                            color: TACTIC_COLORS[t] || "#94a3b8",
                          }}
                        >
                          {t.replace(/-/g, " ")}
                        </span>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>

          {/* Structural Comparison */}
          <Card className="border-border/30 bg-card/50">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-2">
                <BarChart3 className="w-4 h-4 text-primary" />
                Structural Comparison
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-4 gap-4 text-center text-xs">
                {[
                  { label: "Avg Fan-Out", a: comparison.data.avgFanOutA, b: comparison.data.avgFanOutB },
                  { label: "Max Depth", a: comparison.data.maxDepthA, b: comparison.data.maxDepthB },
                  { label: "Edge Count", a: comparison.data.edgeCountA, b: comparison.data.edgeCountB },
                  { label: "Shared Techniques", a: comparison.data.sharedTechniques.length, b: comparison.data.sharedTechniques.length },
                ].map((m) => (
                  <div key={m.label} className="p-3 bg-muted/10 rounded-lg">
                    <div className="text-muted-foreground mb-2">{m.label}</div>
                    <div className="flex items-center justify-center gap-3">
                      <span className="font-semibold text-sm">{m.a}</span>
                      <span className="text-muted-foreground/50">/</span>
                      <span className="font-semibold text-sm">{m.b}</span>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Tabbed Detail Views */}
          <Tabs defaultValue="techniques" className="space-y-4">
            <TabsList className="bg-muted/20">
              <TabsTrigger value="techniques" className="gap-1.5">
                <Target className="w-3.5 h-3.5" />
                Techniques ({comparison.data.allTechniques.length})
              </TabsTrigger>
              <TabsTrigger value="tactics" className="gap-1.5">
                <Layers className="w-3.5 h-3.5" />
                Tactic Coverage
              </TabsTrigger>
              <TabsTrigger value="safety" className="gap-1.5">
                <Shield className="w-3.5 h-3.5" />
                Safety Tiers
              </TabsTrigger>
            </TabsList>

            <TabsContent value="techniques">
              <Card className="border-border/30 bg-card/50">
                <CardContent className="p-4">
                  <TechniqueOverlapTable
                    techniques={comparison.data.allTechniques}
                    nameA={comparison.data.graphA.name}
                    nameB={comparison.data.graphB.name}
                  />
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="tactics">
              <Card className="border-border/30 bg-card/50">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm">Tactic Coverage Comparison</CardTitle>
                  <CardDescription className="text-xs">
                    Technique count per tactic for each graph. Shared techniques are highlighted.
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <TacticCoverageBar coverage={comparison.data.tacticCoverage} />

                  {/* Tactic-only badges */}
                  <div className="mt-4 grid grid-cols-2 gap-4">
                    {comparison.data.tacticsOnlyA.length > 0 && (
                      <div>
                        <div className="text-xs text-muted-foreground mb-1">
                          Only in {comparison.data.graphA.name.split(" — ")[0]}:
                        </div>
                        <div className="flex flex-wrap gap-1">
                          {comparison.data.tacticsOnlyA.map(t => (
                            <Badge key={t} variant="outline" className="text-xs capitalize" style={{ color: TACTIC_COLORS[t] }}>
                              {t.replace(/-/g, " ")}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    )}
                    {comparison.data.tacticsOnlyB.length > 0 && (
                      <div>
                        <div className="text-xs text-muted-foreground mb-1">
                          Only in {comparison.data.graphB.name.split(" — ")[0]}:
                        </div>
                        <div className="flex flex-wrap gap-1">
                          {comparison.data.tacticsOnlyB.map(t => (
                            <Badge key={t} variant="outline" className="text-xs capitalize" style={{ color: TACTIC_COLORS[t] }}>
                              {t.replace(/-/g, " ")}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="safety">
              <Card className="border-border/30 bg-card/50">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm">Safety Tier Distribution</CardTitle>
                  <CardDescription className="text-xs">
                    How nodes are distributed across safety tiers in each graph.
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <SafetyDistributionChart
                    distA={comparison.data.safetyTierDistributionA}
                    distB={comparison.data.safetyTierDistributionB}
                    nameA={comparison.data.graphA.name}
                    nameB={comparison.data.graphB.name}
                  />
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </div>
      )}
    </div>
  );
}
