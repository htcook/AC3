import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Brain,
  RefreshCw,
  Shield,
  Activity,
  Target,
  AlertTriangle,
  TrendingUp,
  Layers,
  Search,
  Zap,
  Database,
  BarChart3,
  ArrowRight,
  ChevronDown,
  ChevronUp,
} from "lucide-react";

export default function ThreatEnrichment() {
  const [selectedKsi, setSelectedKsi] = useState("");
  const [selectedActor, setSelectedActor] = useState("");
  const [selectedTechnique, setSelectedTechnique] = useState("");
  const [selectedModule, setSelectedModule] = useState<string>("ksi");
  const [expandedTheme, setExpandedTheme] = useState<string | null>(null);

  // Queries
  const dashboardStats = trpc.threatEnrichment.getDashboardStats.useQuery();
  const coverageMatrix = trpc.threatEnrichment.getCoverageMatrix.useQuery();
  const ksiEnrichment = trpc.threatEnrichment.enrichKsi.useQuery(
    { ksiId: selectedKsi },
    { enabled: !!selectedKsi }
  );
  const actorImpact = trpc.threatEnrichment.getActorKsiImpact.useQuery(
    { actorId: selectedActor },
    { enabled: !!selectedActor }
  );
  const techniqueCoverage = trpc.threatEnrichment.getTechniqueKsiCoverage.useQuery(
    { techniqueId: selectedTechnique },
    { enabled: !!selectedTechnique }
  );
  const iocFeed = trpc.threatEnrichment.getIocFeedForModule.useQuery(
    { module: selectedModule as any, limit: 25 },
    { enabled: !!selectedModule }
  );

  // Mutations
  const enrichAllKsis = trpc.threatEnrichment.enrichAllKsis.useMutation({
    onSuccess: (data) => {
      toast.success(`Enriched ${data.totalKsis} Key Security Indicators — ${data.highRiskKsis} high risk detected`);
    },
    onError: () => toast.error("Failed to run bulk KSI enrichment"),
  });

  const feedValidation = trpc.threatEnrichment.feedValidationPriorities.useMutation({
    onSuccess: (data) => {
      toast.success(`Updated ${data.totalSchedules} validation priorities — ${data.criticalCount} critical`);
    },
    onError: () => toast.error("Failed to update validation priorities"),
  });

  const feedAttackVectors = trpc.threatEnrichment.feedAttackVectorEnrichment.useMutation({
    onSuccess: (data) => {
      toast.success(`Enriched ${data.totalVectors} attack vectors with threat intelligence`);
    },
    onError: () => toast.error("Failed to enrich attack vectors"),
  });

  const feedConfigBaseline = trpc.threatEnrichment.feedConfigBaselinePriorities.useMutation({
    onSuccess: (data) => {
      toast.success(`Updated config baseline priorities — ${data.priorities.filter((p: any) => p.priority === "critical").length} critical categories`);
    },
    onError: () => toast.error("Failed to update config priorities"),
  });

  const runFullCycle = trpc.threatEnrichment.runFullEnrichmentCycle.useMutation({
    onSuccess: (data) => {
      toast.success(`Full enrichment cycle complete in ${data.duration}ms — ${data.threatDataSummary.actors} actors, ${data.threatDataSummary.ttps} TTPs analyzed`);
      dashboardStats.refetch();
      coverageMatrix.refetch();
    },
    onError: () => toast.error("Failed to run full enrichment cycle"),
  });

  const stats = dashboardStats.data;
  const matrix = coverageMatrix.data;

  const coverageLevelColor = (level: string) => {
    switch (level) {
      case "comprehensive": return "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
      case "good": return "bg-blue-500/10 text-blue-400 border-blue-500/30";
      case "moderate": return "bg-amber-500/10 text-amber-400 border-amber-500/30";
      case "limited": return "bg-red-500/10 text-red-400 border-red-500/30";
      default: return "bg-zinc-500/10 text-zinc-400 border-zinc-500/30";
    }
  };

  const priorityColor = (priority: string) => {
    switch (priority) {
      case "critical": return "bg-red-500/10 text-red-400 border-red-500/30";
      case "high": return "bg-orange-500/10 text-orange-400 border-orange-500/30";
      case "elevated": return "bg-amber-500/10 text-amber-400 border-amber-500/30";
      default: return "bg-zinc-500/10 text-zinc-400 border-zinc-500/30";
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Brain className="h-7 w-7 text-purple-400" />
            Threat Intelligence Enrichment Engine
          </h1>
          <p className="text-muted-foreground mt-1">
            Continuously learns threat actor TTPs and IOCs to enhance Key Security Indicator analysis, monitoring, evaluation, and validation across all platform modules.
          </p>
        </div>
        <Button
          onClick={() => runFullCycle.mutate()}
          disabled={runFullCycle.isPending}
          className="bg-purple-600 hover:bg-purple-700"
        >
          {runFullCycle.isPending ? <RefreshCw className="h-4 w-4 animate-spin mr-2" /> : <Zap className="h-4 w-4 mr-2" />}
          Run Full Enrichment Cycle
        </Button>
      </div>

      {/* Stats Overview */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        {[
          { label: "Threat Actors", value: stats?.totalActors || 0, icon: Target, color: "text-red-400" },
          { label: "IOCs Tracked", value: stats?.totalIocs || 0, icon: AlertTriangle, color: "text-amber-400" },
          { label: "TTPs Mapped", value: stats?.totalTtps || 0, icon: Layers, color: "text-blue-400" },
          { label: "KSIs Covered", value: stats?.totalKsis || 0, icon: Shield, color: "text-emerald-400" },
          { label: "Evidence Items", value: stats?.totalEvidence || 0, icon: Database, color: "text-purple-400" },
          { label: "Attack Vectors", value: stats?.totalVectors || 0, icon: Activity, color: "text-orange-400" },
        ].map((stat) => (
          <Card key={stat.label} className="bg-zinc-900/50 border-zinc-800">
            <CardContent className="p-4">
              <div className="flex items-center gap-2 mb-1">
                <stat.icon className={`h-4 w-4 ${stat.color}`} />
                <span className="text-xs text-muted-foreground">{stat.label}</span>
              </div>
              <p className="text-2xl font-bold">{stat.value.toLocaleString()}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Enrichment Actions */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-4">
            <h3 className="font-semibold text-sm flex items-center gap-2 mb-2">
              <Shield className="h-4 w-4 text-emerald-400" />
              KSI Enrichment
            </h3>
            <p className="text-xs text-muted-foreground mb-3">Enrich all Key Security Indicators with latest threat intelligence</p>
            <Button
              size="sm"
              variant="outline"
              className="w-full"
              onClick={() => enrichAllKsis.mutate()}
              disabled={enrichAllKsis.isPending}
            >
              {enrichAllKsis.isPending ? <RefreshCw className="h-3 w-3 animate-spin mr-1" /> : <TrendingUp className="h-3 w-3 mr-1" />}
              Enrich All KSIs
            </Button>
          </CardContent>
        </Card>

        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-4">
            <h3 className="font-semibold text-sm flex items-center gap-2 mb-2">
              <Activity className="h-4 w-4 text-blue-400" />
              Validation Priorities
            </h3>
            <p className="text-xs text-muted-foreground mb-3">Update validation cadences based on current threat landscape</p>
            <Button
              size="sm"
              variant="outline"
              className="w-full"
              onClick={() => feedValidation.mutate()}
              disabled={feedValidation.isPending}
            >
              {feedValidation.isPending ? <RefreshCw className="h-3 w-3 animate-spin mr-1" /> : <TrendingUp className="h-3 w-3 mr-1" />}
              Feed Validation
            </Button>
          </CardContent>
        </Card>

        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-4">
            <h3 className="font-semibold text-sm flex items-center gap-2 mb-2">
              <Target className="h-4 w-4 text-orange-400" />
              Attack Vector Enrichment
            </h3>
            <p className="text-xs text-muted-foreground mb-3">Score attack vectors with threat actor intelligence</p>
            <Button
              size="sm"
              variant="outline"
              className="w-full"
              onClick={() => feedAttackVectors.mutate()}
              disabled={feedAttackVectors.isPending}
            >
              {feedAttackVectors.isPending ? <RefreshCw className="h-3 w-3 animate-spin mr-1" /> : <TrendingUp className="h-3 w-3 mr-1" />}
              Enrich Vectors
            </Button>
          </CardContent>
        </Card>

        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-4">
            <h3 className="font-semibold text-sm flex items-center gap-2 mb-2">
              <Layers className="h-4 w-4 text-amber-400" />
              Config Baseline Priorities
            </h3>
            <p className="text-xs text-muted-foreground mb-3">Prioritize config rules based on threat actor activity</p>
            <Button
              size="sm"
              variant="outline"
              className="w-full"
              onClick={() => feedConfigBaseline.mutate()}
              disabled={feedConfigBaseline.isPending}
            >
              {feedConfigBaseline.isPending ? <RefreshCw className="h-3 w-3 animate-spin mr-1" /> : <TrendingUp className="h-3 w-3 mr-1" />}
              Feed Config
            </Button>
          </CardContent>
        </Card>
      </div>

      {/* Coverage Matrix */}
      {matrix && (
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <BarChart3 className="h-5 w-5 text-purple-400" />
              KSI Theme Coverage Matrix
            </CardTitle>
            <CardDescription>
              How well the threat catalog covers each FedRAMP Key Security Indicator theme — {matrix.overallCoverage}% overall coverage
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {matrix.matrix.map((row: any) => (
                <div key={row.theme} className="border border-zinc-800 rounded-lg overflow-hidden">
                  <div
                    className="flex items-center justify-between p-3 cursor-pointer hover:bg-zinc-800/50"
                    onClick={() => setExpandedTheme(expandedTheme === row.theme ? null : row.theme)}
                  >
                    <div className="flex items-center gap-3">
                      <span className="font-mono text-sm font-bold text-purple-400 w-8">{row.theme}</span>
                      <span className="text-sm">{row.themeFullName}</span>
                    </div>
                    <div className="flex items-center gap-3">
                      <Badge variant="outline" className={coverageLevelColor(row.coverageLevel)}>
                        {row.coverageLevel}
                      </Badge>
                      <span className="text-xs text-muted-foreground">{row.actorCoverage} actors</span>
                      <span className="text-xs text-muted-foreground">{row.techniqueCount} techniques</span>
                      {row.criticalActors > 0 && (
                        <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/30 text-xs">
                          {row.criticalActors} critical
                        </Badge>
                      )}
                      {expandedTheme === row.theme ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                    </div>
                  </div>
                  {expandedTheme === row.theme && (
                    <div className="p-3 border-t border-zinc-800 bg-zinc-900/30">
                      <div className="grid grid-cols-3 gap-4 text-sm">
                        <div>
                          <p className="text-muted-foreground text-xs mb-1">Actor Coverage</p>
                          <div className="h-2 bg-zinc-800 rounded-full overflow-hidden">
                            <div
                              className="h-full bg-purple-500 rounded-full"
                              style={{ width: `${Math.min(100, (row.actorCoverage / Math.max(1, matrix.totalActors)) * 100 * 5)}%` }}
                            />
                          </div>
                          <p className="text-xs mt-1">{row.actorCoverage} of {matrix.totalActors} actors</p>
                        </div>
                        <div>
                          <p className="text-muted-foreground text-xs mb-1">Technique Mappings</p>
                          <p className="text-lg font-bold">{row.techniqueCount}</p>
                          <p className="text-xs text-muted-foreground">MITRE ATT&CK techniques</p>
                        </div>
                        <div>
                          <p className="text-muted-foreground text-xs mb-1">Critical Actors</p>
                          <p className="text-lg font-bold text-red-400">{row.criticalActors}</p>
                          <p className="text-xs text-muted-foreground">nation-state / APT groups</p>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* KSI-specific Enrichment Lookup */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <Shield className="h-5 w-5 text-emerald-400" />
              KSI Threat Enrichment
            </CardTitle>
            <CardDescription>Look up threat intelligence for a specific Key Security Indicator</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex gap-2 mb-4">
              <Input
                placeholder="Enter KSI ID (e.g., KSI-SVC-VSR)"
                value={selectedKsi}
                onChange={(e) => setSelectedKsi(e.target.value.toUpperCase())}
                className="bg-zinc-800 border-zinc-700"
              />
              <Button
                size="sm"
                variant="outline"
                onClick={() => ksiEnrichment.refetch()}
                disabled={!selectedKsi}
              >
                <Search className="h-4 w-4" />
              </Button>
            </div>
            {ksiEnrichment.data && (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-mono">{ksiEnrichment.data.ksiId}</span>
                  <Badge variant="outline" className={
                    ksiEnrichment.data.riskScore >= 70 ? "bg-red-500/10 text-red-400 border-red-500/30" :
                    ksiEnrichment.data.riskScore >= 40 ? "bg-amber-500/10 text-amber-400 border-amber-500/30" :
                    "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                  }>
                    Risk: {ksiEnrichment.data.riskScore}/100
                  </Badge>
                </div>
                <div className="text-xs text-muted-foreground">
                  {ksiEnrichment.data.threatActors.length} threat actors | {ksiEnrichment.data.techniques.length} techniques | {ksiEnrichment.data.iocs.length} IOCs
                </div>
                {ksiEnrichment.data.threatActors.slice(0, 5).map((actor: any) => (
                  <div key={actor.actorId} className="flex items-center justify-between text-sm border border-zinc-800 rounded p-2">
                    <div className="flex items-center gap-2">
                      <Target className="h-3 w-3 text-red-400" />
                      <span>{actor.name}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className={priorityColor(actor.threatLevel)} >
                        {actor.threatLevel}
                      </Badge>
                      <span className="text-xs text-muted-foreground">{actor.matchedTechniques.length} TTPs</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* IOC Feed by Module */}
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-amber-400" />
              IOC Feed by Module
            </CardTitle>
            <CardDescription>View IOCs relevant to each platform module</CardDescription>
          </CardHeader>
          <CardContent>
            <Select value={selectedModule} onValueChange={setSelectedModule}>
              <SelectTrigger className="bg-zinc-800 border-zinc-700 mb-4">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="ksi">Key Security Indicators</SelectItem>
                <SelectItem value="attack_vectors">Attack Vectors</SelectItem>
                <SelectItem value="config_baseline">Config Baseline</SelectItem>
                <SelectItem value="engagement">Engagement Planning</SelectItem>
                <SelectItem value="validation">Validation</SelectItem>
              </SelectContent>
            </Select>
            {iocFeed.data && (
              <div className="space-y-2">
                <div className="text-xs text-muted-foreground mb-2">
                  {iocFeed.data.totalIocs} IOCs from {iocFeed.data.relevantActors} threat actors
                </div>
                <div className="max-h-64 overflow-y-auto space-y-1">
                  {iocFeed.data.iocs.slice(0, 15).map((ioc: any) => (
                    <div key={ioc.id} className="flex items-center justify-between text-xs border border-zinc-800 rounded p-2">
                      <div className="flex items-center gap-2 min-w-0">
                        <Badge variant="outline" className="text-[10px] shrink-0">{ioc.type}</Badge>
                        <span className="font-mono truncate">{ioc.value}</span>
                      </div>
                      <Badge variant="outline" className={
                        ioc.confidence === "high" ? "bg-red-500/10 text-red-400 border-red-500/30" :
                        ioc.confidence === "medium" ? "bg-amber-500/10 text-amber-400 border-amber-500/30" :
                        "bg-zinc-500/10 text-zinc-400 border-zinc-500/30"
                      }>
                        {ioc.confidence}
                      </Badge>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Actor Impact & Technique Coverage Lookups */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <Target className="h-5 w-5 text-red-400" />
              Threat Actor KSI Impact
            </CardTitle>
            <CardDescription>See which Key Security Indicators a threat actor impacts</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex gap-2 mb-4">
              <Input
                placeholder="Enter Actor ID"
                value={selectedActor}
                onChange={(e) => setSelectedActor(e.target.value)}
                className="bg-zinc-800 border-zinc-700"
              />
              <Button size="sm" variant="outline" onClick={() => actorImpact.refetch()} disabled={!selectedActor}>
                <Search className="h-4 w-4" />
              </Button>
            </div>
            {actorImpact.data?.actor && (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="font-semibold">{actorImpact.data.actor.name}</span>
                  <Badge variant="outline" className={priorityColor(actorImpact.data.actor.threatLevel)}>
                    {actorImpact.data.actor.threatLevel}
                  </Badge>
                </div>
                <div className="text-xs text-muted-foreground">
                  {actorImpact.data.totalImpact} KSIs impacted | {actorImpact.data.actor.techniques} techniques | {actorImpact.data.iocCount} IOCs
                </div>
                <div className="max-h-48 overflow-y-auto space-y-1">
                  {actorImpact.data.impactedKsis.slice(0, 10).map((ksi: any) => (
                    <div key={ksi.ksiId} className="flex items-center justify-between text-xs border border-zinc-800 rounded p-2">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-purple-400">{ksi.ksiId}</span>
                        <ArrowRight className="h-3 w-3 text-muted-foreground" />
                        <span className="truncate">{ksi.ksiName}</span>
                      </div>
                      <Badge variant="outline" className={priorityColor(ksi.impactLevel)}>
                        {ksi.impactLevel}
                      </Badge>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <Layers className="h-5 w-5 text-blue-400" />
              Technique KSI Coverage
            </CardTitle>
            <CardDescription>See which Key Security Indicators cover a MITRE technique</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex gap-2 mb-4">
              <Input
                placeholder="Enter Technique ID (e.g., T1190)"
                value={selectedTechnique}
                onChange={(e) => setSelectedTechnique(e.target.value.toUpperCase())}
                className="bg-zinc-800 border-zinc-700"
              />
              <Button size="sm" variant="outline" onClick={() => techniqueCoverage.refetch()} disabled={!selectedTechnique}>
                <Search className="h-4 w-4" />
              </Button>
            </div>
            {techniqueCoverage.data && (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="font-semibold">{techniqueCoverage.data.techniqueName}</span>
                  <Badge variant="outline">{techniqueCoverage.data.tactic}</Badge>
                </div>
                <div className="text-xs text-muted-foreground">
                  Covered by {techniqueCoverage.data.coveredByKsis.length} KSIs | Used by {techniqueCoverage.data.usedByActors.length} actors |
                  {techniqueCoverage.data.detectionRuleCount} detection rules | {techniqueCoverage.data.iocPatternCount} IOC patterns
                </div>
                <div className="max-h-48 overflow-y-auto space-y-1">
                  {techniqueCoverage.data.coveredByKsis.map((ksi: any) => (
                    <div key={ksi.ksiId} className="flex items-center gap-2 text-xs border border-zinc-800 rounded p-2">
                      <span className="font-mono text-emerald-400">{ksi.ksiId}</span>
                      <span>{ksi.name}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Bulk Enrichment Results */}
      {enrichAllKsis.data && (
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardHeader>
            <CardTitle className="text-lg">Bulk KSI Enrichment Results</CardTitle>
            <CardDescription>
              {enrichAllKsis.data.highRiskKsis} high risk | {enrichAllKsis.data.mediumRiskKsis} medium risk | {enrichAllKsis.data.lowRiskKsis} low risk
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
              {enrichAllKsis.data.results.slice(0, 15).map((result: any) => (
                <div key={result.ksiId} className="flex items-center justify-between text-sm border border-zinc-800 rounded p-2">
                  <div>
                    <span className="font-mono text-xs text-purple-400">{result.ksiId}</span>
                    <p className="text-xs text-muted-foreground truncate">{result.ksiName}</p>
                  </div>
                  <div className="text-right">
                    <Badge variant="outline" className={
                      result.riskScore >= 70 ? "bg-red-500/10 text-red-400 border-red-500/30" :
                      result.riskScore >= 40 ? "bg-amber-500/10 text-amber-400 border-amber-500/30" :
                      "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                    }>
                      {result.riskScore}
                    </Badge>
                    <p className="text-[10px] text-muted-foreground mt-1">{result.actorCount} actors</p>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Validation Priority Feed Results */}
      {feedValidation.data && (
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardHeader>
            <CardTitle className="text-lg">Validation Priority Updates</CardTitle>
            <CardDescription>
              {feedValidation.data.criticalCount} critical | {feedValidation.data.highCount} high | {feedValidation.data.elevatedCount} elevated | {feedValidation.data.normalCount} normal
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="max-h-64 overflow-y-auto space-y-1">
              {feedValidation.data.priorityUpdates
                .filter((p: any) => p.newPriority !== "normal")
                .slice(0, 20)
                .map((update: any) => (
                  <div key={update.ksiId} className="flex items-center justify-between text-sm border border-zinc-800 rounded p-2">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs">{update.ksiId}</span>
                      <span className="text-xs text-muted-foreground truncate">{update.reason}</span>
                    </div>
                    <Badge variant="outline" className={priorityColor(update.newPriority)}>
                      {update.newPriority}
                    </Badge>
                  </div>
                ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
