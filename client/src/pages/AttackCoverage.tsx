import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Map, Target, Shield, AlertTriangle, CheckCircle2,
  BarChart3, Layers, Activity
} from "lucide-react";
import AppShell from "@/components/AppShell";

const COVERAGE_COLORS: Record<string, string> = {
  high: "bg-emerald-500/20 text-emerald-400 border-emerald-500/40",
  medium: "bg-amber-500/20 text-amber-400 border-amber-500/40",
  low: "bg-red-500/20 text-red-400 border-red-500/40",
  none: "bg-gray-500/10 text-gray-500 border-gray-500/20",
};

const COVERAGE_BG: Record<string, string> = {
  high: "bg-emerald-500/10 border-emerald-500/30",
  medium: "bg-amber-500/10 border-amber-500/30",
  low: "bg-red-500/10 border-red-500/30",
  none: "bg-gray-500/5 border-gray-500/20",
};

export default function AttackCoverage() {
  const [activeTab, setActiveTab] = useState("heatmap");

  const heatmapQuery = trpc.attackCoverage.getHeatmap.useQuery();
  const gapsQuery = trpc.attackCoverage.getCoverageGaps.useQuery();

  const heatmap = heatmapQuery.data;
  const gaps = gapsQuery.data || [];

  return (
    <AppShell activePath="/attack-coverage">
      <div className="space-y-6 p-1">
        {/* Header */}
        <div>
          <h1 className="text-2xl font-bold tracking-tight flex items-center gap-3">
            <Map className="w-7 h-7 text-cyan-400" />
            MITRE ATT&CK Coverage
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Unified ATT&CK coverage heatmap aggregating technique coverage from all integrated tools — Caldera, Atomic Red Team, ZAP, Nuclei, Sliver C2, Metasploit, and GoPhish.
          </p>
        </div>

        {/* Summary Cards */}
        {heatmap && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <Card className="border-border/50">
              <CardContent className="pt-4 pb-3">
                <p className="text-xs text-muted-foreground">Tactics Covered</p>
                <p className="text-2xl font-bold text-emerald-400">
                  {heatmap.summary.coveredTactics}/{heatmap.summary.totalTactics}
                </p>
              </CardContent>
            </Card>
            <Card className="border-border/50">
              <CardContent className="pt-4 pb-3">
                <p className="text-xs text-muted-foreground">Total Techniques</p>
                <p className="text-2xl font-bold text-purple-400">{heatmap.summary.totalTechniques.toLocaleString()}</p>
              </CardContent>
            </Card>
            <Card className="border-border/50">
              <CardContent className="pt-4 pb-3">
                <p className="text-xs text-muted-foreground">Integrated Tools</p>
                <p className="text-2xl font-bold text-cyan-400">{heatmap.tools.length}</p>
              </CardContent>
            </Card>
            <Card className="border-border/50">
              <CardContent className="pt-4 pb-3">
                <p className="text-xs text-muted-foreground">Avg Tools/Tactic</p>
                <p className="text-2xl font-bold text-amber-400">{heatmap.summary.averageToolsPerTactic}</p>
              </CardContent>
            </Card>
          </div>
        )}

        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="bg-card border border-border">
            <TabsTrigger value="heatmap">Coverage Heatmap</TabsTrigger>
            <TabsTrigger value="tools">Tool Breakdown</TabsTrigger>
            <TabsTrigger value="gaps">Coverage Gaps</TabsTrigger>
          </TabsList>

          {/* Heatmap */}
          <TabsContent value="heatmap" className="space-y-3">
            {heatmap?.tactics.map((tactic: any) => (
              <Card key={tactic.tacticId} className={`border ${COVERAGE_BG[tactic.coverageLevel]}`}>
                <CardContent className="py-4">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-3">
                      <Badge variant="outline" className={COVERAGE_COLORS[tactic.coverageLevel]}>
                        {tactic.coverageLevel.toUpperCase()}
                      </Badge>
                      <div>
                        <p className="font-medium">{tactic.tacticName}</p>
                        <p className="text-xs text-muted-foreground">{tactic.tacticId}</p>
                      </div>
                    </div>
                    <span className="text-sm font-mono text-muted-foreground">{tactic.toolsCovering} tools</span>
                  </div>
                  <div className="flex flex-wrap gap-1.5 mt-2">
                    {tactic.tools.map((t: any) => (
                      <Badge key={t.tool} variant="outline" className="text-xs" style={{ borderColor: t.color + "80", color: t.color }}>
                        {t.tool}
                      </Badge>
                    ))}
                  </div>
                </CardContent>
              </Card>
            ))}
          </TabsContent>

          {/* Tool Breakdown */}
          <TabsContent value="tools" className="space-y-3">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {heatmap?.tools.map((tool: any) => (
                <Card key={tool.tool} className="border-border/50">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-base flex items-center gap-2">
                      <div className="w-3 h-3 rounded-full" style={{ backgroundColor: tool.color }} />
                      {tool.tool}
                    </CardTitle>
                    <CardDescription>{tool.label}</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm text-muted-foreground">Techniques</span>
                      <span className="font-bold">{tool.techniqueCount}</span>
                    </div>
                    <div className="flex items-center justify-between mb-3">
                      <span className="text-sm text-muted-foreground">Tactics Covered</span>
                      <span className="font-bold">{tool.tactics.length}/14</span>
                    </div>
                    <div className="w-full bg-gray-800 rounded-full h-2">
                      <div className="h-2 rounded-full" style={{ width: `${(tool.tactics.length / 14) * 100}%`, backgroundColor: tool.color }} />
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </TabsContent>

          {/* Coverage Gaps */}
          <TabsContent value="gaps" className="space-y-3">
            {gaps.length === 0 ? (
              <Card className="border-emerald-500/30">
                <CardContent className="flex flex-col items-center justify-center py-16 text-center">
                  <CheckCircle2 className="w-12 h-12 text-emerald-400 mb-4" />
                  <p className="text-emerald-400 font-medium">All tactics have adequate coverage.</p>
                </CardContent>
              </Card>
            ) : (
              gaps.map((gap: any) => (
                <Card key={gap.tacticId} className="border-red-500/20">
                  <CardContent className="py-4">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <AlertTriangle className="w-4 h-4 text-amber-400" />
                        <p className="font-medium">{gap.tacticName}</p>
                        <span className="text-xs text-muted-foreground">({gap.tacticId})</span>
                      </div>
                      <Badge variant="outline" className="text-red-400 border-red-500/30">
                        {gap.toolsCovering} tool(s)
                      </Badge>
                    </div>
                    <p className="text-sm text-muted-foreground">{gap.recommendation}</p>
                    {gap.tools.length > 0 && (
                      <div className="flex gap-1.5 mt-2">
                        {gap.tools.map((t: string) => (
                          <Badge key={t} variant="outline" className="text-xs">{t}</Badge>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>
              ))
            )}
          </TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
}
