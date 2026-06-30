import { trpc } from "@/lib/trpc";
import AppShell from "@/components/AppShell";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Shield, ChevronLeft, Loader2, Activity, Eye,
  AlertTriangle, CheckCircle2, XCircle, TrendingUp,
  FileText, ExternalLink, Target, Gauge, BarChart3,
  Lightbulb, Fingerprint, Clock
} from "lucide-react";
import { Link, useParams } from "wouter";
import { useMemo } from "react";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-300 border-red-500/40",
  high: "bg-orange-500/20 text-orange-300 border-orange-500/40",
  medium: "bg-yellow-500/20 text-yellow-300 border-yellow-500/40",
  low: "bg-blue-500/20 text-blue-300 border-blue-500/40",
  info: "bg-gray-500/20 text-gray-300 border-gray-500/40",
};

const SIGNAL_TYPE_ICONS: Record<string, typeof Activity> = {
  vulnerability: AlertTriangle,
  exposure: Eye,
  weak_signal: TrendingUp,
  intel: FileText,
  hygiene: CheckCircle2,
  misconfiguration: XCircle,
};

function ScoreGauge({ score, label, color }: { score: number; label: string; color: string }) {
  const percentage = Math.min(100, Math.max(0, (score / 10) * 100));
  return (
    <div className="flex flex-col items-center">
      <div className="relative w-20 h-20">
        <svg className="w-20 h-20 -rotate-90" viewBox="0 0 80 80">
          <circle cx="40" cy="40" r="34" fill="none" stroke="currentColor" strokeWidth="6"
            className="text-muted/20" />
          <circle cx="40" cy="40" r="34" fill="none" stroke="currentColor" strokeWidth="6"
            className={color}
            strokeDasharray={`${percentage * 2.136} ${213.6 - percentage * 2.136}`}
            strokeLinecap="round" />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className={`text-lg font-bold ${color}`}>{score.toFixed(1)}</span>
        </div>
      </div>
      <span className="text-xs text-muted-foreground mt-1">{label}</span>
    </div>
  );
}

function RiskScoreBadge({ score }: { score: number }) {
  const config = score >= 9 ? { label: "CRITICAL", color: "bg-red-600 text-white", ring: "ring-red-500/50" }
    : score >= 7 ? { label: "HIGH", color: "bg-orange-600 text-white", ring: "ring-orange-500/50" }
    : score >= 4 ? { label: "MEDIUM", color: "bg-yellow-600 text-white", ring: "ring-yellow-500/50" }
    : score >= 2 ? { label: "LOW", color: "bg-blue-600 text-white", ring: "ring-blue-500/50" }
    : { label: "INFO", color: "bg-gray-600 text-white", ring: "ring-gray-500/50" };

  return (
    <div className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg ${config.color} ring-2 ${config.ring}`}>
      <Shield className="h-5 w-5" />
      <span className="text-2xl font-bold">{score.toFixed(2)}</span>
      <span className="text-sm font-medium opacity-80">/10</span>
      <Badge className="ml-1 bg-white/20 text-white border-0 text-xs">{config.label}</Badge>
    </div>
  );
}

export default function SSILRiskCardDetail() {
  const params = useParams<{ riskId: string }>();
  const riskId = params.riskId ? decodeURIComponent(params.riskId) : "";

  const { data, isLoading, error } = trpc.ssil.getRiskCard.useQuery(
    { riskId },
    { enabled: !!riskId }
  );

  const card = data?.card;
  const signals = data?.signals || [];
  const observations = data?.observations || [];

  // Group observations by scanner
  const obsByScanner = useMemo(() => {
    const grouped = new Map<string, any[]>();
    for (const obs of observations) {
      const scanner = obs.scannerName || "unknown";
      if (!grouped.has(scanner)) grouped.set(scanner, []);
      grouped.get(scanner)!.push(obs);
    }
    return grouped;
  }, [observations]);

  // Group signals by type
  const sigsByType = useMemo(() => {
    const grouped = new Map<string, any[]>();
    for (const sig of signals) {
      const type = sig.signalType || "unknown";
      if (!grouped.has(type)) grouped.set(type, []);
      grouped.get(type)!.push(sig);
    }
    return grouped;
  }, [signals]);

  if (isLoading) {
    return (
      <AppShell>
        <div className="flex items-center justify-center py-20">
          <Loader2 className="h-8 w-8 animate-spin text-red-400" />
        </div>
      </AppShell>
    );
  }

  if (error || !card) {
    return (
      <AppShell>
        <div className="space-y-6">
          <div className="flex items-center gap-4">
            <Link href="/ssil/observations">
              <Button variant="ghost" size="icon">
                <ChevronLeft className="h-4 w-4" />
              </Button>
            </Link>
            <h1 className="text-2xl font-bold">Risk Card Not Found</h1>
          </div>
          <Card className="border-red-500/20 bg-card/50">
            <CardContent className="p-8 text-center text-muted-foreground">
              <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>The requested risk card could not be found.</p>
              <p className="text-xs mt-2">Risk ID: {riskId}</p>
            </CardContent>
          </Card>
        </div>
      </AppShell>
    );
  }

  return (
    <AppShell>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Link href="/ssil/observations">
              <Button variant="ghost" size="icon">
                <ChevronLeft className="h-4 w-4" />
              </Button>
            </Link>
            <div>
              <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
                <Shield className="h-6 w-6 text-red-400" />
                Risk Card Detail
              </h1>
              <p className="text-muted-foreground mt-1 font-mono text-sm">
                {card.assetId}
              </p>
            </div>
          </div>
          <RiskScoreBadge score={card.finalScore} />
        </div>

        {/* Score Breakdown */}
        <Card className="border-red-500/20 bg-card/50">
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <Gauge className="h-5 w-5 text-red-400" />
              Hybrid Risk Score Breakdown
            </CardTitle>
            <CardDescription>
              Final score = (CVSS × 0.40 + Hybrid × 0.40 + BIA × 0.20) × Confidence
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-around py-4">
              <ScoreGauge score={card.componentCvss} label="CVSS (40%)" color="text-red-400" />
              <div className="text-2xl text-muted-foreground">×</div>
              <ScoreGauge score={card.componentCarver} label="Hybrid Score (40%)" color="text-orange-400" />
              <div className="text-2xl text-muted-foreground">×</div>
              <ScoreGauge score={card.componentBia} label="BIA (20%)" color="text-yellow-400" />
              <div className="text-2xl text-muted-foreground">×</div>
              <div className="flex flex-col items-center">
                <div className="w-20 h-20 rounded-full border-4 border-cyan-500/40 flex items-center justify-center">
                  <span className="text-lg font-bold text-cyan-400">
                    {(card.confidenceWeight * 100).toFixed(0)}%
                  </span>
                </div>
                <span className="text-xs text-muted-foreground mt-1">Confidence</span>
              </div>
              <div className="text-2xl text-muted-foreground">=</div>
              <div className="flex flex-col items-center">
                <div className={`w-24 h-24 rounded-full border-4 flex items-center justify-center ${
                  card.finalScore >= 8 ? "border-red-500/60" :
                  card.finalScore >= 6 ? "border-orange-500/60" :
                  card.finalScore >= 4 ? "border-yellow-500/60" :
                  "border-green-500/60"
                }`}>
                  <span className={`text-2xl font-bold ${
                    card.finalScore >= 8 ? "text-red-400" :
                    card.finalScore >= 6 ? "text-orange-400" :
                    card.finalScore >= 4 ? "text-yellow-400" :
                    "text-green-400"
                  }`}>
                    {card.finalScore.toFixed(2)}
                  </span>
                </div>
                <span className="text-xs text-muted-foreground mt-1">Final Score</span>
              </div>
            </div>

            {/* Summary & Why It Matters */}
            <div className="mt-6 space-y-4">
              <div className="p-4 rounded-lg bg-muted/10 border border-border/20">
                <h4 className="text-sm font-semibold mb-1 flex items-center gap-1.5">
                  <FileText className="h-4 w-4 text-amber-400" />
                  Summary
                </h4>
                <p className="text-sm text-muted-foreground">{card.summary}</p>
              </div>
              {card.whyItMatters && (
                <div className="p-4 rounded-lg bg-muted/10 border border-border/20">
                  <h4 className="text-sm font-semibold mb-1 flex items-center gap-1.5">
                    <Lightbulb className="h-4 w-4 text-yellow-400" />
                    Why It Matters
                  </h4>
                  <p className="text-sm text-muted-foreground">{card.whyItMatters}</p>
                </div>
              )}
            </div>

            {/* Metadata */}
            <div className="mt-4 flex items-center gap-4 text-xs text-muted-foreground">
              <div className="flex items-center gap-1">
                <Fingerprint className="h-3 w-3" />
                <span className="font-mono">{card.riskId}</span>
              </div>
              <div className="flex items-center gap-1">
                <Clock className="h-3 w-3" />
                <span>Created: {new Date(card.createdAt).toLocaleString()}</span>
              </div>
              {(card as any).updatedAt && (
                <div className="flex items-center gap-1">
                  <Clock className="h-3 w-3" />
                  <span>Updated: {new Date((card as any).updatedAt).toLocaleString()}</span>
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Recommendations */}
        {card.recommendations && (card.recommendations as string[]).length > 0 && (
          <Card className="border-amber-500/20 bg-card/50">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <Lightbulb className="h-5 w-5 text-amber-400" />
                Recommended Remediations ({(card.recommendations as string[]).length})
              </CardTitle>
              <CardDescription>
                Prioritized actions to reduce risk for this asset
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {(card.recommendations as string[]).map((rec: string, i: number) => (
                  <div key={i} className="flex items-start gap-3 p-3 rounded-lg bg-muted/10 border border-border/20">
                    <div className={`flex-shrink-0 w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold ${
                      i === 0 ? "bg-red-500/20 text-red-300 border border-red-500/40" :
                      i === 1 ? "bg-orange-500/20 text-orange-300 border border-orange-500/40" :
                      i === 2 ? "bg-yellow-500/20 text-yellow-300 border border-yellow-500/40" :
                      "bg-muted/30 text-muted-foreground border border-border/40"
                    }`}>
                      {i + 1}
                    </div>
                    <p className="text-sm text-foreground leading-relaxed">{rec}</p>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Contributing Signals */}
        <Card className="border-purple-500/20 bg-card/50">
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <Activity className="h-5 w-5 text-purple-400" />
              Contributing Signals ({signals.length})
            </CardTitle>
            <CardDescription>
              Intelligence signals that contributed to this risk assessment
            </CardDescription>
          </CardHeader>
          <CardContent>
            {signals.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                <Activity className="h-8 w-8 mx-auto mb-2 opacity-50" />
                <p>No contributing signals found for this risk card.</p>
              </div>
            ) : (
              <div className="space-y-4">
                {Array.from(sigsByType.entries()).map(([type, typeSigs]) => {
                  const Icon = SIGNAL_TYPE_ICONS[type] || Activity;
                  return (
                    <div key={type}>
                      <h4 className="text-sm font-semibold mb-2 flex items-center gap-1.5 capitalize">
                        <Icon className="h-4 w-4 text-purple-400" />
                        {type.replace("_", " ")} ({typeSigs.length})
                      </h4>
                      <div className="space-y-2 ml-6">
                        {typeSigs.map((sig: any) => (
                          <div key={sig.id} className="p-3 rounded-lg border border-border/30 bg-muted/5">
                            <div className="flex items-center justify-between mb-1">
                              <div className="flex items-center gap-2">
                                <Badge className={`${SEVERITY_COLORS[sig.severity || sig.signalSeverity] || SEVERITY_COLORS.info} text-xs`}>
                                  {sig.severity || sig.signalSeverity}
                                </Badge>
                                <span className="text-sm font-semibold">{sig.category}</span>
                                <span className="text-xs text-muted-foreground font-mono">
                                  conf: {((sig.confidence || sig.signalConfidence || 0) * 100).toFixed(0)}%
                                </span>
                              </div>
                              <div className="flex items-center gap-2">
                                {sig.enrichmentCve && (
                                  <Badge variant="outline" className="text-xs text-red-300 border-red-500/40">
                                    {sig.enrichmentCve}
                                  </Badge>
                                )}
                                {sig.enrichmentCvss && (
                                  <span className="text-xs font-mono text-orange-300">
                                    CVSS: {sig.enrichmentCvss}
                                  </span>
                                )}
                              </div>
                            </div>
                            <p className="text-xs text-muted-foreground">{sig.rationale}</p>
                            {sig.enrichmentReferences && (sig.enrichmentReferences as string[]).length > 0 && (
                              <div className="mt-2 flex flex-wrap gap-1">
                                {(sig.enrichmentReferences as string[]).slice(0, 3).map((ref: string, i: number) => (
                                  <a key={i} href={ref} target="_blank" rel="noopener noreferrer"
                                    className="inline-flex items-center gap-1 text-[10px] text-cyan-400 hover:text-cyan-300">
                                    <ExternalLink className="h-2.5 w-2.5" />
                                    {ref.length > 40 ? ref.slice(0, 40) + "..." : ref}
                                  </a>
                                ))}
                              </div>
                            )}
                            <div className="mt-1 text-[10px] text-muted-foreground font-mono">
                              Signal: {sig.signalId} | Sources: {((sig.sourceObservations as string[]) || []).length} observations
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Evidence Artifacts (Observations) */}
        <Card className="border-amber-500/20 bg-card/50">
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <Eye className="h-5 w-5 text-amber-400" />
              Evidence Artifacts ({observations.length})
            </CardTitle>
            <CardDescription>
              Raw observations from scanner adapters that form the evidence base for this risk assessment
            </CardDescription>
          </CardHeader>
          <CardContent>
            {observations.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                <Eye className="h-8 w-8 mx-auto mb-2 opacity-50" />
                <p>No evidence artifacts found for this risk card.</p>
              </div>
            ) : (
              <div className="space-y-4">
                {Array.from(obsByScanner.entries()).map(([scanner, scannerObs]) => (
                  <div key={scanner}>
                    <h4 className="text-sm font-semibold mb-2 flex items-center gap-1.5">
                      <Target className="h-4 w-4 text-amber-400" />
                      {scanner} ({scannerObs.length} observations)
                    </h4>
                    <div className="space-y-2 ml-6">
                      {scannerObs.map((obs: any) => (
                        <div key={obs.id} className="p-3 rounded-lg border border-border/20 bg-muted/5">
                          <div className="flex items-center justify-between mb-1">
                            <div className="flex items-center gap-2">
                              <Badge className={`${SEVERITY_COLORS[obs.severity] || SEVERITY_COLORS.info} text-xs`}>
                                {obs.severity}
                              </Badge>
                              <span className="text-xs text-muted-foreground">{obs.observationType}</span>
                              <span className="text-xs font-mono text-muted-foreground">
                                {obs.assetHost}:{obs.assetPort}
                              </span>
                            </div>
                            <div className="flex items-center gap-2 text-xs text-muted-foreground">
                              <span>conf: {((obs.confidence || 0) * 100).toFixed(0)}%</span>
                              {obs.evidenceCve && (
                                <Badge variant="outline" className="text-[10px] text-red-300 border-red-500/40">
                                  {obs.evidenceCve}
                                </Badge>
                              )}
                            </div>
                          </div>
                          <p className="text-xs text-muted-foreground">{obs.evidenceSummary}</p>
                          <div className="mt-1.5 grid grid-cols-3 gap-2 text-[10px] text-muted-foreground">
                            <div>
                              <span className="opacity-60">Adapter:</span> {obs.scannerAdapter}
                            </div>
                            <div>
                              <span className="opacity-60">Mode:</span> {obs.scannerMode}
                            </div>
                            <div>
                              <span className="opacity-60">Protocol:</span> {obs.assetProtocol}
                            </div>
                          </div>
                          {obs.evidenceHash && (
                            <div className="mt-1 text-[10px] font-mono text-muted-foreground opacity-60">
                              <Fingerprint className="h-2.5 w-2.5 inline mr-1" />
                              {obs.evidenceHash}
                            </div>
                          )}
                          <div className="mt-1 text-[10px] text-muted-foreground opacity-60">
                            Observed: {new Date(obs.observedAt).toLocaleString()} | ID: {obs.observationId}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Evidence List from Card */}
        {card.evidence && (card.evidence as string[]).length > 0 && (
          <Card className="border-border/50 bg-card/50">
            <CardHeader>
              <CardTitle className="text-sm flex items-center gap-2">
                <Fingerprint className="h-4 w-4 text-muted-foreground" />
                Evidence Observation IDs ({(card.evidence as string[]).length})
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-1">
                {(card.evidence as string[]).map((evidenceId: string, i: number) => (
                  <Badge key={i} variant="outline" className="text-[10px] font-mono">
                    {evidenceId}
                  </Badge>
                ))}
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </AppShell>
  );
}
