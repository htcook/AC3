import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { useParams, useLocation } from "wouter";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { Streamdown } from "streamdown";
import {
  ArrowLeft, Shield, Target, AlertTriangle, Brain, Globe, Server,
  ChevronDown, ChevronUp, Crosshair, Zap, FileText, ExternalLink,
  Activity, Lock, Eye, Network, Loader2, BarChart3
} from "lucide-react";

const RISK_COLORS: Record<string, string> = {
  critical: "text-red-400 bg-red-500/20 border-red-500/40",
  high: "text-orange-400 bg-orange-500/20 border-orange-500/40",
  medium: "text-yellow-400 bg-yellow-500/20 border-yellow-500/40",
  low: "text-emerald-400 bg-emerald-500/20 border-emerald-500/40",
};

const RISK_BAR_COLORS: Record<string, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-emerald-500",
};

function RiskGauge({ score, band, size = "lg" }: { score: number; band: string; size?: "sm" | "lg" }) {
  const radius = size === "lg" ? 60 : 35;
  const stroke = size === "lg" ? 8 : 5;
  const circumference = 2 * Math.PI * radius;
  const progress = (score / 100) * circumference;
  const color = band === "critical" ? "#ef4444" : band === "high" ? "#f97316" : band === "medium" ? "#eab308" : "#22c55e";

  return (
    <div className="relative inline-flex items-center justify-center">
      <svg width={(radius + stroke) * 2} height={(radius + stroke) * 2} className="-rotate-90">
        <circle cx={radius + stroke} cy={radius + stroke} r={radius} fill="none" stroke="currentColor" strokeWidth={stroke} className="text-muted/30" />
        <circle cx={radius + stroke} cy={radius + stroke} r={radius} fill="none" stroke={color} strokeWidth={stroke}
          strokeDasharray={circumference} strokeDashoffset={circumference - progress} strokeLinecap="round" className="transition-all duration-1000" />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className={`font-bold ${size === "lg" ? "text-3xl" : "text-lg"}`} style={{ color }}>{score}</span>
        {size === "lg" && <span className="text-xs text-muted-foreground uppercase">{band}</span>}
      </div>
    </div>
  );
}

function CarverRadar({ scores }: { scores: Record<string, number> }) {
  const labels = ["Criticality", "Accessibility", "Recuperability", "Vulnerability", "Effect", "Recognizability"];
  const keys = ["criticality", "accessibility", "recuperability", "vulnerability", "effect", "recognizability"];
  const cx = 100, cy = 100, r = 70;

  const points = keys.map((k, i) => {
    const angle = (Math.PI * 2 * i) / keys.length - Math.PI / 2;
    const val = (scores[k] || 0) / 10;
    return {
      x: cx + r * val * Math.cos(angle),
      y: cy + r * val * Math.sin(angle),
      lx: cx + (r + 18) * Math.cos(angle),
      ly: cy + (r + 18) * Math.sin(angle),
      label: labels[i],
      value: scores[k] || 0,
    };
  });

  const polygon = points.map(p => `${p.x},${p.y}`).join(" ");

  return (
    <svg viewBox="0 0 200 200" className="w-full max-w-[220px]">
      {[0.25, 0.5, 0.75, 1].map(scale => (
        <polygon key={scale} points={keys.map((_, i) => {
          const angle = (Math.PI * 2 * i) / keys.length - Math.PI / 2;
          return `${cx + r * scale * Math.cos(angle)},${cy + r * scale * Math.sin(angle)}`;
        }).join(" ")} fill="none" stroke="currentColor" strokeWidth="0.5" className="text-muted/30" />
      ))}
      {keys.map((_, i) => {
        const angle = (Math.PI * 2 * i) / keys.length - Math.PI / 2;
        return <line key={i} x1={cx} y1={cy} x2={cx + r * Math.cos(angle)} y2={cy + r * Math.sin(angle)} stroke="currentColor" strokeWidth="0.5" className="text-muted/30" />;
      })}
      <polygon points={polygon} fill="rgba(168,85,247,0.2)" stroke="rgb(168,85,247)" strokeWidth="1.5" />
      {points.map((p, i) => (
        <g key={i}>
          <circle cx={p.x} cy={p.y} r="3" fill="rgb(168,85,247)" />
          <text x={p.lx} y={p.ly} textAnchor="middle" dominantBaseline="middle" className="fill-muted-foreground text-[6px]">{p.label.slice(0, 4)}</text>
        </g>
      ))}
    </svg>
  );
}

export default function DomainIntelResults() {
  const params = useParams<{ id: string }>();
  const [, navigate] = useLocation();
  const scanId = Number(params.id);
  const [expandedAsset, setExpandedAsset] = useState<number | null>(null);
  const [expandedCampaign, setExpandedCampaign] = useState<string | null>(null);

  const { data, isLoading, error } = trpc.domainIntel.getScan.useQuery({ id: scanId }, { enabled: !!scanId });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-purple-400" />
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="text-center py-12">
        <AlertTriangle className="h-12 w-12 text-destructive mx-auto mb-4" />
        <p className="text-lg font-semibold">Scan not found</p>
        <Button variant="outline" className="mt-4" onClick={() => navigate("/domain-intel")}>
          <ArrowLeft className="h-4 w-4 mr-2" /> Back to Domain Intel
        </Button>
      </div>
    );
  }

  const { scan, assets } = data;
  const pipeline = scan.pipelineOutput as any;
  const campaigns = (scan.campaignRecommendations || []) as any[];

  // Sort assets by risk score descending
  const sortedAssets = [...assets].sort((a: any, b: any) => (b.hybridRiskScore || 0) - (a.hybridRiskScore || 0));

  // Risk distribution
  const riskDist = { critical: 0, high: 0, medium: 0, low: 0 };
  assets.forEach((a: any) => {
    const band = a.riskBand || "low";
    if (band in riskDist) riskDist[band as keyof typeof riskDist]++;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Button variant="ghost" size="icon" onClick={() => navigate("/domain-intel")}>
          <ArrowLeft className="h-5 w-5" />
        </Button>
        <div className="flex-1">
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Brain className="h-7 w-7 text-purple-400" />
            <span className="font-mono">{scan.primaryDomain}</span>
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            {scan.clientType?.toUpperCase()} &middot; {scan.sector} &middot; {assets.length} assets discovered &middot; Scanned {new Date(scan.createdAt).toLocaleDateString()}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <RiskGauge score={scan.overallRiskScore || 0} band={scan.overallRiskBand || "low"} />
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Card>
          <CardContent className="p-4 text-center">
            <p className="text-3xl font-bold">{assets.length}</p>
            <p className="text-xs text-muted-foreground mt-1">Assets Discovered</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <p className="text-3xl font-bold">{scan.totalFindings || 0}</p>
            <p className="text-xs text-muted-foreground mt-1">Posture Findings</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <p className="text-3xl font-bold">{campaigns.length}</p>
            <p className="text-xs text-muted-foreground mt-1">Campaigns Designed</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="space-y-1">
              {Object.entries(riskDist).map(([band, count]) => (
                <div key={band} className="flex items-center gap-2 text-xs">
                  <div className={`w-2 h-2 rounded-full ${RISK_BAR_COLORS[band]}`} />
                  <span className="capitalize flex-1">{band}</span>
                  <span className="font-mono">{count}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Tabs */}
      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList className="grid grid-cols-5 w-full max-w-2xl">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="assets">Assets</TabsTrigger>
          <TabsTrigger value="campaigns">Campaigns</TabsTrigger>
          <TabsTrigger value="threat-model">Threat Model</TabsTrigger>
          <TabsTrigger value="findings">Findings</TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-6">
          {/* Executive Summary */}
          {scan.executiveSummary && (
            <Card>
              <CardHeader>
                <CardTitle className="text-sm flex items-center gap-2">
                  <FileText className="h-4 w-4 text-purple-400" />
                  Executive Summary
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="prose prose-sm prose-invert max-w-none">
                  <Streamdown>{scan.executiveSummary}</Streamdown>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Risk Heatmap */}
          <Card>
            <CardHeader>
              <CardTitle className="text-sm flex items-center gap-2">
                <BarChart3 className="h-4 w-4 text-purple-400" />
                Asset Risk Heatmap
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-2">
                {sortedAssets.map((asset: any) => {
                  const band = asset.riskBand || "low";
                  return (
                    <div
                      key={asset.id}
                      className={`p-2 rounded-lg border cursor-pointer transition-all hover:scale-105 ${RISK_COLORS[band]}`}
                      onClick={() => setExpandedAsset(expandedAsset === asset.id ? null : asset.id)}
                    >
                      <p className="font-mono text-xs truncate">{asset.hostname}</p>
                      <div className="flex items-center justify-between mt-1">
                        <span className="text-xs opacity-70">{asset.assetType}</span>
                        <span className="text-sm font-bold">{asset.hybridRiskScore}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </CardContent>
          </Card>

          {/* Top Campaigns Preview */}
          {campaigns.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-sm flex items-center gap-2">
                  <Crosshair className="h-4 w-4 text-purple-400" />
                  Recommended Campaigns
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {campaigns.slice(0, 4).map((c: any) => (
                    <div key={c.id} className="p-3 rounded-lg border border-border bg-muted/30">
                      <div className="flex items-center justify-between mb-2">
                        <p className="font-semibold text-sm">{c.name}</p>
                        <Badge className={RISK_COLORS[c.priority] || RISK_COLORS.medium}>{c.priority}</Badge>
                      </div>
                      <p className="text-xs text-muted-foreground line-clamp-2">{c.description}</p>
                      <div className="flex gap-1 mt-2 flex-wrap">
                        <Badge variant="outline" className="text-[10px]">{c.type}</Badge>
                        {(c.mitreTactics || []).slice(0, 3).map((t: string) => (
                          <Badge key={t} variant="secondary" className="text-[10px]">{t}</Badge>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Assets Tab */}
        <TabsContent value="assets" className="space-y-3">
          {sortedAssets.map((asset: any) => {
            const isExpanded = expandedAsset === asset.id;
            const band = asset.riskBand || "low";
            const carver = (asset.carverScores || {}) as Record<string, number>;
            const shock = (asset.shockScores || {}) as Record<string, number>;
            const findings = (asset.postureFindings || []) as any[];
            const vectors = (asset.testVectors || []) as any[];

            return (
              <Card key={asset.id} className={`transition-all ${isExpanded ? "ring-1 ring-purple-500/40" : ""}`}>
                <div
                  className="p-4 cursor-pointer flex items-center gap-4"
                  onClick={() => setExpandedAsset(isExpanded ? null : asset.id)}
                >
                  <div className={`w-10 h-10 rounded-lg flex items-center justify-center shrink-0 ${RISK_COLORS[band]}`}>
                    <span className="text-sm font-bold">{asset.hybridRiskScore}</span>
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <p className="font-mono font-semibold text-sm truncate">{asset.hostname}</p>
                      <Badge variant="outline" className="text-[10px] shrink-0">{asset.assetType}</Badge>
                    </div>
                    <div className="flex gap-1 mt-1 flex-wrap">
                      {((asset.tags || []) as string[]).slice(0, 4).map((t: string) => (
                        <Badge key={t} variant="secondary" className="text-[10px]">{t}</Badge>
                      ))}
                      {((asset.tags || []) as string[]).length > 4 && (
                        <Badge variant="secondary" className="text-[10px]">+{((asset.tags || []) as string[]).length - 4}</Badge>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    <Badge className={`${RISK_COLORS[band]} text-xs`}>{band}</Badge>
                    <Badge variant="outline" className="text-[10px]">{asset.suggestedTier?.replace("_", " ")}</Badge>
                    {isExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                  </div>
                </div>

                {isExpanded && (
                  <CardContent className="pt-0 pb-4 space-y-4 border-t border-border">
                    {/* CARVER + SHOCK Scores */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
                      <div>
                        <p className="text-xs font-medium text-muted-foreground mb-2">CARVER Scores</p>
                        <div className="flex items-center gap-4">
                          <CarverRadar scores={carver} />
                          <div className="space-y-1.5 flex-1">
                            {Object.entries(carver).map(([k, v]) => (
                              <div key={k} className="flex items-center gap-2">
                                <span className="text-[10px] text-muted-foreground w-20 capitalize">{k}</span>
                                <Progress value={(v as number) * 10} className="h-1.5 flex-1" />
                                <span className="text-xs font-mono w-6 text-right">{v as number}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>
                      <div>
                        <p className="text-xs font-medium text-muted-foreground mb-2">SHOCK Scores</p>
                        <div className="space-y-1.5">
                          {Object.entries(shock).map(([k, v]) => (
                            <div key={k} className="flex items-center gap-2">
                              <span className="text-[10px] text-muted-foreground w-28 capitalize">{k.replace(/([A-Z])/g, " $1").trim()}</span>
                              <Progress value={(v as number) * 10} className="h-1.5 flex-1" />
                              <span className="text-xs font-mono w-6 text-right">{v as number}</span>
                            </div>
                          ))}
                        </div>
                        <div className="mt-3 flex gap-4 text-xs">
                          <div>
                            <span className="text-muted-foreground">Mission Impact:</span>{" "}
                            <span className="font-bold">{(asset.missionImpactScore || 0) / 10}/10</span>
                          </div>
                          <div>
                            <span className="text-muted-foreground">CVSS Est:</span>{" "}
                            <span className="font-bold">{(asset.cvssEstimate || 0) / 10}/10</span>
                          </div>
                          <div>
                            <span className="text-muted-foreground">Confidence:</span>{" "}
                            <span className="font-bold">{asset.confidence || 0}%</span>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Posture Findings */}
                    {findings.length > 0 && (
                      <div>
                        <p className="text-xs font-medium text-muted-foreground mb-2">Posture Findings ({findings.length})</p>
                        <div className="space-y-2">
                          {findings.map((f: any, i: number) => (
                            <div key={i} className="p-2 rounded bg-muted/30 border border-border">
                              <div className="flex items-center justify-between">
                                <p className="text-sm font-medium">{f.title}</p>
                                <div className="flex gap-2">
                                  <Badge variant="outline" className="text-[10px]">Sev: {f.severity}/10</Badge>
                                  <Badge variant="outline" className="text-[10px]">Likely: {f.likelihood}/10</Badge>
                                </div>
                              </div>
                              {f.recommendedControls && f.recommendedControls.length > 0 && (
                                <div className="mt-1 flex gap-1 flex-wrap">
                                  {f.recommendedControls.map((c: string, j: number) => (
                                    <Badge key={j} variant="secondary" className="text-[10px]">{c}</Badge>
                                  ))}
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Test Vectors */}
                    {vectors.length > 0 && (
                      <div>
                        <p className="text-xs font-medium text-muted-foreground mb-2">Test Vectors ({vectors.length})</p>
                        <div className="space-y-2">
                          {vectors.map((v: any, i: number) => (
                            <div key={i} className="p-2 rounded bg-purple-500/5 border border-purple-500/20">
                              <div className="flex items-center gap-2 mb-1">
                                <Crosshair className="h-3 w-3 text-purple-400" />
                                <span className="text-sm font-medium">{v.vectorType}</span>
                                {v.suggestedEmulation?.technique && (
                                  <Badge className="bg-purple-500/20 text-purple-400 text-[10px]">{v.suggestedEmulation.technique}</Badge>
                                )}
                              </div>
                              <p className="text-xs text-muted-foreground">{v.hypothesis}</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </CardContent>
                )}
              </Card>
            );
          })}
        </TabsContent>

        {/* Campaigns Tab */}
        <TabsContent value="campaigns" className="space-y-4">
          {campaigns.length === 0 ? (
            <Card>
              <CardContent className="p-8 text-center text-muted-foreground">
                No campaign recommendations generated.
              </CardContent>
            </Card>
          ) : (
            campaigns.map((c: any) => {
              const isExpanded = expandedCampaign === c.id;
              return (
                <Card key={c.id} className={`transition-all ${isExpanded ? "ring-1 ring-purple-500/40" : ""}`}>
                  <div
                    className="p-4 cursor-pointer"
                    onClick={() => setExpandedCampaign(isExpanded ? null : c.id)}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <div className={`p-2 rounded-lg ${RISK_COLORS[c.priority] || RISK_COLORS.medium}`}>
                          <Crosshair className="h-4 w-4" />
                        </div>
                        <div>
                          <p className="font-semibold">{c.name}</p>
                          <p className="text-xs text-muted-foreground mt-0.5">{c.description?.slice(0, 120)}...</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <Badge className={RISK_COLORS[c.priority]}>{c.priority}</Badge>
                        <Badge variant="outline">{c.type?.replace("_", " ")}</Badge>
                        {isExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                      </div>
                    </div>
                  </div>

                  {isExpanded && (
                    <CardContent className="pt-0 pb-4 space-y-4 border-t border-border">
                      <p className="text-sm text-muted-foreground mt-3">{c.description}</p>

                      {/* Target Assets */}
                      {c.targetAssets?.length > 0 && (
                        <div>
                          <p className="text-xs font-medium text-muted-foreground mb-2">Target Assets</p>
                          <div className="flex gap-1 flex-wrap">
                            {c.targetAssets.map((a: string) => (
                              <Badge key={a} variant="secondary" className="font-mono text-[10px]">{a}</Badge>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* MITRE Tactics */}
                      {c.mitreTactics?.length > 0 && (
                        <div>
                          <p className="text-xs font-medium text-muted-foreground mb-2">MITRE ATT&CK Tactics</p>
                          <div className="flex gap-1 flex-wrap">
                            {c.mitreTactics.map((t: string) => (
                              <Badge key={t} className="bg-purple-500/20 text-purple-400 text-[10px]">{t}</Badge>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Attack Chain */}
                      {c.attackChain?.length > 0 && (
                        <div>
                          <p className="text-xs font-medium text-muted-foreground mb-2">Attack Chain</p>
                          <div className="space-y-2">
                            {c.attackChain.map((step: any, i: number) => (
                              <div key={i} className="flex items-start gap-3">
                                <div className="w-6 h-6 rounded-full bg-purple-500/20 flex items-center justify-center shrink-0 mt-0.5">
                                  <span className="text-[10px] font-bold text-purple-400">{step.step}</span>
                                </div>
                                <div className="flex-1">
                                  <div className="flex items-center gap-2">
                                    <span className="text-sm font-medium">{step.phase}</span>
                                    <Badge variant="outline" className="text-[10px]">{step.technique}</Badge>
                                  </div>
                                  <p className="text-xs text-muted-foreground">{step.action}</p>
                                  <Badge variant="secondary" className="text-[10px] mt-1">{step.tool}</Badge>
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Caldera Abilities */}
                      {c.calderaAbilities?.length > 0 && (
                        <div>
                          <p className="text-xs font-medium text-muted-foreground mb-2">
                            <Shield className="h-3 w-3 inline mr-1" />
                            Caldera Abilities
                          </p>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                            {c.calderaAbilities.map((a: any, i: number) => (
                              <div key={i} className="p-2 rounded bg-red-500/5 border border-red-500/20">
                                <div className="flex items-center gap-2">
                                  <Target className="h-3 w-3 text-red-400" />
                                  <span className="text-sm font-medium">{a.name}</span>
                                </div>
                                <div className="flex gap-1 mt-1">
                                  <Badge variant="outline" className="text-[10px]">{a.tactic}</Badge>
                                  <Badge className="bg-red-500/20 text-red-400 text-[10px]">{a.technique}</Badge>
                                </div>
                                <p className="text-xs text-muted-foreground mt-1">{a.rationale}</p>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* GoPhish Templates */}
                      {c.gophishTemplates?.length > 0 && (
                        <div>
                          <p className="text-xs font-medium text-muted-foreground mb-2">
                            <Zap className="h-3 w-3 inline mr-1" />
                            GoPhish Templates
                          </p>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                            {c.gophishTemplates.map((t: any, i: number) => (
                              <div key={i} className="p-2 rounded bg-blue-500/5 border border-blue-500/20">
                                <p className="text-sm font-medium">{t.name}</p>
                                <p className="text-xs text-muted-foreground mt-0.5">Subject: {t.subject}</p>
                                <div className="flex gap-1 mt-1">
                                  <Badge variant="outline" className="text-[10px]">{t.theme}</Badge>
                                  <Badge variant="secondary" className="text-[10px]">{t.targetPersona}</Badge>
                                </div>
                                <p className="text-xs text-muted-foreground mt-1">{t.rationale}</p>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Create Engagement Button */}
                      <div className="pt-2">
                        <Button
                          size="sm"
                          className="bg-purple-600 hover:bg-purple-700"
                          onClick={(e) => {
                            e.stopPropagation();
                            navigate(`/engagements/new?fromIntel=${scanId}&campaign=${c.id}`);
                          }}
                        >
                          <Zap className="h-4 w-4 mr-2" />
                          Create Engagement from This Campaign
                        </Button>
                      </div>
                    </CardContent>
                  )}
                </Card>
              );
            })
          )}
        </TabsContent>

        {/* Threat Model Tab */}
        <TabsContent value="threat-model" className="space-y-4">
          {scan.threatModelSummary && (
            <Card>
              <CardHeader>
                <CardTitle className="text-sm flex items-center gap-2">
                  <Brain className="h-4 w-4 text-purple-400" />
                  Threat Model Analysis
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="prose prose-sm prose-invert max-w-none">
                  <Streamdown>{scan.threatModelSummary}</Streamdown>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Tier Distribution */}
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Asset Tier Distribution</CardTitle>
              <CardDescription>CARVER+SHOCK-based prioritization tiers</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-4 gap-3">
                {["tier0_critical", "tier1_high", "tier2_medium", "tier3_low"].map(tier => {
                  const count = assets.filter((a: any) => a.suggestedTier === tier).length;
                  const label = tier.replace("_", " ").replace("tier", "Tier ");
                  const colors: Record<string, string> = {
                    tier0_critical: "bg-red-500/20 text-red-400 border-red-500/40",
                    tier1_high: "bg-orange-500/20 text-orange-400 border-orange-500/40",
                    tier2_medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/40",
                    tier3_low: "bg-emerald-500/20 text-emerald-400 border-emerald-500/40",
                  };
                  return (
                    <div key={tier} className={`p-3 rounded-lg border text-center ${colors[tier]}`}>
                      <p className="text-2xl font-bold">{count}</p>
                      <p className="text-xs capitalize mt-1">{label}</p>
                    </div>
                  );
                })}
              </div>
            </CardContent>
          </Card>

          {/* Attack Surface Summary */}
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Attack Surface by Asset Type</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {Object.entries(
                  assets.reduce((acc: Record<string, number>, a: any) => {
                    const t = a.assetType || "unknown";
                    acc[t] = (acc[t] || 0) + 1;
                    return acc;
                  }, {} as Record<string, number>)
                ).sort(([, a], [, b]) => (b as number) - (a as number)).map(([type, count]) => (
                  <div key={type} className="flex items-center gap-3">
                    <span className="text-xs text-muted-foreground w-32 capitalize">{type.replace(/_/g, " ")}</span>
                    <Progress value={((count as number) / assets.length) * 100} className="h-2 flex-1" />
                    <span className="text-xs font-mono w-6 text-right">{count as number}</span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Findings Tab */}
        <TabsContent value="findings" className="space-y-3">
          {(() => {
            const allFindings = assets.flatMap((a: any) =>
              ((a.postureFindings || []) as any[]).map((f: any) => ({ ...f, assetHostname: a.hostname, assetRisk: a.hybridRiskScore }))
            ).sort((a: any, b: any) => (b.severity || 0) - (a.severity || 0));

            if (allFindings.length === 0) {
              return (
                <Card>
                  <CardContent className="p-8 text-center text-muted-foreground">
                    No posture findings detected.
                  </CardContent>
                </Card>
              );
            }

            return allFindings.map((f: any, i: number) => (
              <Card key={i}>
                <CardContent className="p-4">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <AlertTriangle className={`h-4 w-4 ${
                          f.severity >= 8 ? "text-red-400" : f.severity >= 6 ? "text-orange-400" : f.severity >= 4 ? "text-yellow-400" : "text-emerald-400"
                        }`} />
                        <p className="font-semibold text-sm">{f.title}</p>
                      </div>
                      <p className="text-xs text-muted-foreground">
                        Asset: <span className="font-mono">{f.assetHostname || f.assetRef}</span>
                      </p>
                    </div>
                    <div className="flex gap-2 shrink-0">
                      <Badge variant="outline" className="text-[10px]">Severity: {f.severity}/10</Badge>
                      <Badge variant="outline" className="text-[10px]">Likelihood: {f.likelihood}/10</Badge>
                    </div>
                  </div>
                  {f.recommendedControls?.length > 0 && (
                    <div className="mt-2 flex gap-1 flex-wrap">
                      <span className="text-[10px] text-muted-foreground mr-1">Controls:</span>
                      {f.recommendedControls.map((c: string, j: number) => (
                        <Badge key={j} variant="secondary" className="text-[10px]">{c}</Badge>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>
            ));
          })()}
        </TabsContent>
      </Tabs>
    </div>
  );
}
