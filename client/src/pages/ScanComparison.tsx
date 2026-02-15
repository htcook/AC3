import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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
  ArrowLeftRight, TrendingUp, TrendingDown, Minus, Shield,
  AlertTriangle, Plus, X, ChevronDown, ChevronUp, ExternalLink,
  Calendar, Globe, Bug, CheckCircle, Clock, HelpCircle,
} from "lucide-react";

function riskBandColor(band: string) {
  switch (band) {
    case "critical": return "text-red-400 bg-red-500/10 border-red-500/30";
    case "high": return "text-orange-400 bg-orange-500/10 border-orange-500/30";
    case "medium": return "text-yellow-400 bg-yellow-500/10 border-yellow-500/30";
    case "low": return "text-green-400 bg-green-500/10 border-green-500/30";
    default: return "text-muted-foreground bg-muted/30 border-border";
  }
}

function tierBadge(tier: string) {
  switch (tier) {
    case "confirmed": return <Badge className="bg-green-600/80 text-white text-[10px] px-1.5 py-0"><CheckCircle className="h-2.5 w-2.5 mr-0.5" />Confirmed</Badge>;
    case "probable": return <Badge className="bg-yellow-600/80 text-white text-[10px] px-1.5 py-0"><Clock className="h-2.5 w-2.5 mr-0.5" />Probable</Badge>;
    case "potential": return <Badge className="bg-zinc-600/80 text-white text-[10px] px-1.5 py-0"><HelpCircle className="h-2.5 w-2.5 mr-0.5" />Potential</Badge>;
    default: return null;
  }
}

function DeltaIndicator({ value, suffix = "" }: { value: number; suffix?: string }) {
  if (value > 0) return <span className="text-red-400 flex items-center gap-0.5"><TrendingUp className="h-3.5 w-3.5" />+{value}{suffix}</span>;
  if (value < 0) return <span className="text-green-400 flex items-center gap-0.5"><TrendingDown className="h-3.5 w-3.5" />{value}{suffix}</span>;
  return <span className="text-muted-foreground flex items-center gap-0.5"><Minus className="h-3.5 w-3.5" />No change</span>;
}

export default function ScanComparison() {
  const [scanIdA, setScanIdA] = useState<string>("");
  const [scanIdB, setScanIdB] = useState<string>("");
  const [showNewFindings, setShowNewFindings] = useState(true);
  const [showResolvedFindings, setShowResolvedFindings] = useState(true);

  // Fetch all completed scans for the dropdown
  const { data: scans, isLoading: scansLoading } = trpc.domainIntel.listScans.useQuery();

  const completedScans = useMemo(() => {
    return (scans || []).filter((s: any) => s.status === "completed").sort((a: any, b: any) => {
      const dateA = new Date(a.createdAt).getTime();
      const dateB = new Date(b.createdAt).getTime();
      return dateB - dateA;
    });
  }, [scans]);

  // Fetch comparison data
  const { data: comparison, isLoading: comparisonLoading, error: comparisonError } =
    trpc.domainIntel.compareScans.useQuery(
      { scanIdA: Number(scanIdA), scanIdB: Number(scanIdB) },
      { enabled: !!scanIdA && !!scanIdB && scanIdA !== scanIdB }
    );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <ArrowLeftRight className="h-6 w-6 text-blue-500" />
          Scan Comparison
        </h1>
        <p className="text-sm text-muted-foreground mt-1">
          Compare two domain intelligence scans side-by-side to track how risk posture changed over time. Select a baseline scan and a comparison scan to see new assets, resolved vulnerabilities, and risk score changes.
        </p>
      </div>

      {/* Scan Selection */}
      <Card className="border-border/50 bg-card/50">
        <CardContent className="pt-6">
          <div className="grid grid-cols-1 md:grid-cols-[1fr_auto_1fr] gap-4 items-end">
            <div className="space-y-2">
              <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Baseline Scan (Before)</label>
              <Select value={scanIdA} onValueChange={setScanIdA}>
                <SelectTrigger>
                  <SelectValue placeholder="Select baseline scan..." />
                </SelectTrigger>
                <SelectContent>
                  {completedScans.map((s: any) => (
                    <SelectItem key={s.id} value={String(s.id)} disabled={String(s.id) === scanIdB}>
                      #{s.id} — {s.primaryDomain} — {new Date(s.createdAt).toLocaleDateString()}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="flex items-center justify-center pb-1">
              <ArrowLeftRight className="h-5 w-5 text-muted-foreground" />
            </div>

            <div className="space-y-2">
              <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Comparison Scan (After)</label>
              <Select value={scanIdB} onValueChange={setScanIdB}>
                <SelectTrigger>
                  <SelectValue placeholder="Select comparison scan..." />
                </SelectTrigger>
                <SelectContent>
                  {completedScans.map((s: any) => (
                    <SelectItem key={s.id} value={String(s.id)} disabled={String(s.id) === scanIdA}>
                      #{s.id} — {s.primaryDomain} — {new Date(s.createdAt).toLocaleDateString()}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Loading / Error States */}
      {comparisonLoading && (
        <div className="text-center py-12 text-muted-foreground">
          <ArrowLeftRight className="h-8 w-8 mx-auto mb-3 animate-pulse" />
          <p>Comparing scans...</p>
        </div>
      )}

      {comparisonError && (
        <div className="text-center py-12 text-red-400">
          <AlertTriangle className="h-8 w-8 mx-auto mb-3" />
          <p>Error loading comparison: {comparisonError.message}</p>
        </div>
      )}

      {!scanIdA || !scanIdB ? (
        <div className="text-center py-12 text-muted-foreground">
          <ArrowLeftRight className="h-8 w-8 mx-auto mb-3 opacity-30" />
          <p>Select two completed scans above to compare</p>
        </div>
      ) : scanIdA === scanIdB ? (
        <div className="text-center py-12 text-yellow-400">
          <AlertTriangle className="h-8 w-8 mx-auto mb-3" />
          <p>Please select two different scans to compare</p>
        </div>
      ) : null}

      {/* Comparison Results */}
      {comparison && (
        <>
          {/* Overview Cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <Card className="border-border/50 bg-card/50">
              <CardContent className="pt-4 pb-3 text-center">
                <p className="text-xs text-muted-foreground mb-1">Overall Risk Delta</p>
                <div className="text-2xl font-bold">
                  <DeltaIndicator value={comparison.riskDelta} />
                </div>
              </CardContent>
            </Card>

            <Card className="border-border/50 bg-card/50">
              <CardContent className="pt-4 pb-3 text-center">
                <p className="text-xs text-muted-foreground mb-1">Asset Changes</p>
                <div className="flex items-center justify-center gap-3 text-sm">
                  <span className="text-green-400">+{comparison.newAssets.length} new</span>
                  <span className="text-red-400">-{comparison.removedAssets.length} removed</span>
                </div>
              </CardContent>
            </Card>

            <Card className="border-border/50 bg-card/50">
              <CardContent className="pt-4 pb-3 text-center">
                <p className="text-xs text-muted-foreground mb-1">CVE Changes</p>
                <div className="flex items-center justify-center gap-3 text-sm">
                  <span className="text-red-400">+{comparison.newCves.length} new</span>
                  <span className="text-green-400">-{comparison.resolvedCves.length} resolved</span>
                </div>
              </CardContent>
            </Card>

            <Card className="border-border/50 bg-card/50">
              <CardContent className="pt-4 pb-3 text-center">
                <p className="text-xs text-muted-foreground mb-1">Finding Changes</p>
                <div className="flex items-center justify-center gap-3 text-sm">
                  <span className="text-red-400">+{comparison.newFindings.length} new</span>
                  <span className="text-green-400">-{comparison.resolvedFindings.length} resolved</span>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Side-by-Side Scan Summary */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card className="border-border/50 bg-card/50">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Calendar className="h-4 w-4 text-blue-400" />
                  Baseline: Scan #{comparison.scanA.id}
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Domain</span>
                  <span>{comparison.scanA.primaryDomain}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Date</span>
                  <span>{new Date(comparison.scanA.createdAt).toLocaleString()}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Risk Score</span>
                  <Badge className={riskBandColor(comparison.scanA.overallRiskBand)}>
                    {comparison.scanA.overallRiskScore}/100 ({comparison.scanA.overallRiskBand})
                  </Badge>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Assets</span>
                  <span>{comparison.scanA.totalAssets}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Findings</span>
                  <span>{comparison.scanA.totalFindings}</span>
                </div>
                {comparison.tierComparison && (
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground">Tiers</span>
                    <div className="flex gap-1.5">
                      <span className="text-green-400 text-xs">{comparison.tierComparison.scanA.confirmed}C</span>
                      <span className="text-yellow-400 text-xs">{comparison.tierComparison.scanA.probable}P</span>
                      <span className="text-zinc-400 text-xs">{comparison.tierComparison.scanA.potential}T</span>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>

            <Card className="border-border/50 bg-card/50">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Calendar className="h-4 w-4 text-purple-400" />
                  Comparison: Scan #{comparison.scanB.id}
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Domain</span>
                  <span>{comparison.scanB.primaryDomain}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Date</span>
                  <span>{new Date(comparison.scanB.createdAt).toLocaleString()}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Risk Score</span>
                  <Badge className={riskBandColor(comparison.scanB.overallRiskBand)}>
                    {comparison.scanB.overallRiskScore}/100 ({comparison.scanB.overallRiskBand})
                  </Badge>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Assets</span>
                  <span>{comparison.scanB.totalAssets}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Findings</span>
                  <span>{comparison.scanB.totalFindings}</span>
                </div>
                {comparison.tierComparison && (
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground">Tiers</span>
                    <div className="flex gap-1.5">
                      <span className="text-green-400 text-xs">{comparison.tierComparison.scanB.confirmed}C</span>
                      <span className="text-yellow-400 text-xs">{comparison.tierComparison.scanB.probable}P</span>
                      <span className="text-zinc-400 text-xs">{comparison.tierComparison.scanB.potential}T</span>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Risk Changes Per Asset */}
          {comparison.riskChanges.length > 0 && (
            <Card className="border-border/50 bg-card/50">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <TrendingUp className="h-4 w-4 text-orange-400" />
                  Risk Score Changes by Asset ({comparison.riskChanges.length})
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {comparison.riskChanges.map((rc: any) => (
                    <div key={rc.hostname} className="flex items-center justify-between p-2 rounded border border-border/30 bg-background/50 text-sm">
                      <div className="flex items-center gap-2">
                        <Globe className="h-3.5 w-3.5 text-muted-foreground" />
                        <span className="font-mono text-xs">{rc.hostname}</span>
                      </div>
                      <div className="flex items-center gap-3">
                        <Badge className={riskBandColor(rc.bandA)}>{rc.riskA}</Badge>
                        <span className="text-muted-foreground">→</span>
                        <Badge className={riskBandColor(rc.bandB)}>{rc.riskB}</Badge>
                        <span className="text-xs w-16 text-right">
                          <DeltaIndicator value={rc.delta} />
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* New Assets */}
          {comparison.newAssets.length > 0 && (
            <Card className="border-border/50 bg-card/50">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Plus className="h-4 w-4 text-green-400" />
                  New Assets Discovered ({comparison.newAssets.length})
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  {comparison.newAssets.map((a: any) => (
                    <div key={a.hostname} className="flex items-center justify-between p-2 rounded border border-green-500/20 bg-green-500/5 text-sm">
                      <div className="flex items-center gap-2">
                        <Globe className="h-3.5 w-3.5 text-green-400" />
                        <span className="font-mono text-xs">{a.hostname}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className="text-[10px]">{a.assetType}</Badge>
                        {a.discoveryMethod && (
                          <Badge variant="outline" className="text-[10px]">{a.discoveryMethod}</Badge>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Removed Assets */}
          {comparison.removedAssets.length > 0 && (
            <Card className="border-border/50 bg-card/50">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <X className="h-4 w-4 text-red-400" />
                  Assets No Longer Detected ({comparison.removedAssets.length})
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  {comparison.removedAssets.map((a: any) => (
                    <div key={a.hostname} className="flex items-center justify-between p-2 rounded border border-red-500/20 bg-red-500/5 text-sm">
                      <div className="flex items-center gap-2">
                        <Globe className="h-3.5 w-3.5 text-red-400" />
                        <span className="font-mono text-xs">{a.hostname}</span>
                      </div>
                      <Badge variant="outline" className="text-[10px]">{a.assetType}</Badge>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* New CVEs */}
          {comparison.newCves.length > 0 && (
            <Card className="border-border/50 bg-card/50">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Bug className="h-4 w-4 text-red-400" />
                  New CVEs ({comparison.newCves.length})
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-1.5">
                  {comparison.newCves.map((cve: string) => (
                    <a
                      key={cve}
                      href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 px-2 py-0.5 rounded border border-red-500/30 bg-red-500/10 text-red-400 text-xs hover:bg-red-500/20 transition-colors"
                    >
                      {cve}
                      <ExternalLink className="h-2.5 w-2.5" />
                    </a>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Resolved CVEs */}
          {comparison.resolvedCves.length > 0 && (
            <Card className="border-border/50 bg-card/50">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Shield className="h-4 w-4 text-green-400" />
                  Resolved CVEs ({comparison.resolvedCves.length})
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-1.5">
                  {comparison.resolvedCves.map((cve: string) => (
                    <span
                      key={cve}
                      className="inline-flex items-center gap-1 px-2 py-0.5 rounded border border-green-500/30 bg-green-500/10 text-green-400 text-xs line-through"
                    >
                      {cve}
                    </span>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* New Findings */}
          {comparison.newFindings.length > 0 && (
            <Card className="border-border/50 bg-card/50">
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4 text-red-400" />
                    New Findings ({comparison.newFindings.length})
                  </CardTitle>
                  <Button variant="ghost" size="sm" onClick={() => setShowNewFindings(!showNewFindings)}>
                    {showNewFindings ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                  </Button>
                </div>
              </CardHeader>
              {showNewFindings && (
                <CardContent>
                  <div className="space-y-2">
                    {comparison.newFindings.map((f: any) => (
                      <div key={f.id} className="p-2.5 rounded border border-red-500/20 bg-red-500/5 text-sm">
                        <div className="flex items-start justify-between gap-2">
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-1.5 flex-wrap">
                              {tierBadge(f.corroborationTier)}
                              <Badge variant="outline" className="text-[10px]">{f.category}</Badge>
                              <span className="text-[10px] text-muted-foreground">Sev: {f.severity}/10</span>
                            </div>
                            <p className="text-xs mt-1 truncate">{f.title}</p>
                            {f.assetHostname && (
                              <p className="text-[10px] text-muted-foreground mt-0.5">Asset: {f.assetHostname}</p>
                            )}
                          </div>
                          <div className="flex gap-1">
                            {(f.cveIds || []).map((cve: string) => (
                              <a
                                key={cve}
                                href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-[10px] text-blue-400 hover:underline"
                              >
                                {cve}
                              </a>
                            ))}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              )}
            </Card>
          )}

          {/* Resolved Findings */}
          {comparison.resolvedFindings.length > 0 && (
            <Card className="border-border/50 bg-card/50">
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Shield className="h-4 w-4 text-green-400" />
                    Resolved Findings ({comparison.resolvedFindings.length})
                  </CardTitle>
                  <Button variant="ghost" size="sm" onClick={() => setShowResolvedFindings(!showResolvedFindings)}>
                    {showResolvedFindings ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                  </Button>
                </div>
              </CardHeader>
              {showResolvedFindings && (
                <CardContent>
                  <div className="space-y-2">
                    {comparison.resolvedFindings.map((f: any) => (
                      <div key={f.id} className="p-2.5 rounded border border-green-500/20 bg-green-500/5 text-sm opacity-80">
                        <div className="flex items-start justify-between gap-2">
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-1.5 flex-wrap">
                              {tierBadge(f.corroborationTier)}
                              <Badge variant="outline" className="text-[10px]">{f.category}</Badge>
                              <span className="text-[10px] text-muted-foreground">Sev: {f.severity}/10</span>
                            </div>
                            <p className="text-xs mt-1 truncate line-through">{f.title}</p>
                            {f.assetHostname && (
                              <p className="text-[10px] text-muted-foreground mt-0.5">Asset: {f.assetHostname}</p>
                            )}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              )}
            </Card>
          )}

          {/* Corroboration Tier Comparison */}
          {comparison.tierComparison && (
            <Card className="border-border/50 bg-card/50">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <CheckCircle className="h-4 w-4 text-blue-400" />
                  Evidence Quality Comparison
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-3 gap-4 text-center">
                  <div>
                    <p className="text-xs text-muted-foreground mb-2">Confirmed</p>
                    <div className="flex items-center justify-center gap-2">
                      <span className="text-lg font-bold text-green-400">{comparison.tierComparison.scanA.confirmed}</span>
                      <span className="text-muted-foreground">→</span>
                      <span className="text-lg font-bold text-green-400">{comparison.tierComparison.scanB.confirmed}</span>
                    </div>
                    <DeltaIndicator value={comparison.tierComparison.scanB.confirmed - comparison.tierComparison.scanA.confirmed} />
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground mb-2">Probable</p>
                    <div className="flex items-center justify-center gap-2">
                      <span className="text-lg font-bold text-yellow-400">{comparison.tierComparison.scanA.probable}</span>
                      <span className="text-muted-foreground">→</span>
                      <span className="text-lg font-bold text-yellow-400">{comparison.tierComparison.scanB.probable}</span>
                    </div>
                    <DeltaIndicator value={comparison.tierComparison.scanB.probable - comparison.tierComparison.scanA.probable} />
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground mb-2">Potential</p>
                    <div className="flex items-center justify-center gap-2">
                      <span className="text-lg font-bold text-zinc-400">{comparison.tierComparison.scanA.potential}</span>
                      <span className="text-muted-foreground">→</span>
                      <span className="text-lg font-bold text-zinc-400">{comparison.tierComparison.scanB.potential}</span>
                    </div>
                    <DeltaIndicator value={comparison.tierComparison.scanB.potential - comparison.tierComparison.scanA.potential} />
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </>
      )}
    </div>
  );
}
