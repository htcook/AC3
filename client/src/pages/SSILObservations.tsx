import { trpc } from "@/lib/trpc";
import AppShell from "@/components/AppShell";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  FileStack, ChevronLeft, Loader2, Eye, AlertTriangle,
  BarChart3, TrendingUp, Shield, Activity
} from "lucide-react";
import { Link } from "wouter";
import { useState, useMemo } from "react";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-300 border-red-500/40",
  high: "bg-orange-500/20 text-orange-300 border-orange-500/40",
  medium: "bg-yellow-500/20 text-yellow-300 border-yellow-500/40",
  low: "bg-blue-500/20 text-blue-300 border-blue-500/40",
  info: "bg-gray-500/20 text-gray-300 border-gray-500/40",
};

const TYPE_LABELS: Record<string, string> = {
  service_banner: "Service Banner",
  tls: "TLS Certificate",
  http_headers: "HTTP Headers",
  dns: "DNS Records",
  vulnerability_finding: "Vulnerability",
  misconfiguration: "Misconfiguration",
  exposure_surface: "Exposure Surface",
  cloud_fingerprint: "Cloud Fingerprint",
};

export default function SSILObservations() {
  const [filters, setFilters] = useState({
    scannerName: undefined as string | undefined,
    observationType: undefined as string | undefined,
    severity: undefined as string | undefined,
    limit: 50,
    offset: 0,
  });

  const stableFilters = useMemo(() => filters, [
    filters.scannerName,
    filters.observationType,
    filters.severity,
    filters.limit,
    filters.offset,
  ]);

  const { data: observations, isLoading: obsLoading } = trpc.ssil.listObservations.useQuery(stableFilters);
  const { data: stats, isLoading: statsLoading } = trpc.ssil.getObservationStats.useQuery();
  const { data: signals } = trpc.ssil.listSignals.useQuery({ limit: 20 });
  const { data: riskCards } = trpc.ssil.listRiskCards.useQuery({ limit: 10 });

  const [selectedObs, setSelectedObs] = useState<string | null>(null);
  const { data: obsDetail } = trpc.ssil.getObservation.useQuery(
    { observationId: selectedObs! },
    { enabled: !!selectedObs }
  );

  const isLoading = obsLoading || statsLoading;

  return (
    <AppShell>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center gap-4">
          <Link href="/ssil">
            <Button variant="ghost" size="icon">
              <ChevronLeft className="h-4 w-4" />
            </Button>
          </Link>
          <div>
            <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
              <FileStack className="h-6 w-6 text-amber-400" />
              Observation Normalizer
            </h1>
            <p className="text-muted-foreground mt-1">
              Unified scan observations from all scanner adapters with signal derivation and risk cards
            </p>
          </div>
        </div>

        {isLoading ? (
          <div className="flex items-center justify-center py-20">
            <Loader2 className="h-8 w-8 animate-spin text-amber-400" />
          </div>
        ) : (
          <>
            {/* Stats Overview */}
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
              <Card className="border-amber-500/20 bg-card/50">
                <CardContent className="p-4 text-center">
                  <div className="text-2xl font-bold text-amber-300">{stats?.totalObservations || 0}</div>
                  <div className="text-xs text-muted-foreground">Observations</div>
                </CardContent>
              </Card>
              <Card className="border-purple-500/20 bg-card/50">
                <CardContent className="p-4 text-center">
                  <div className="text-2xl font-bold text-purple-300">{stats?.totalSignals || 0}</div>
                  <div className="text-xs text-muted-foreground">Signals</div>
                </CardContent>
              </Card>
              <Card className="border-red-500/20 bg-card/50">
                <CardContent className="p-4 text-center">
                  <div className="text-2xl font-bold text-red-300">{stats?.totalRiskCards || 0}</div>
                  <div className="text-xs text-muted-foreground">Risk Cards</div>
                </CardContent>
              </Card>
              <Card className="border-cyan-500/20 bg-card/50">
                <CardContent className="p-4 text-center">
                  <div className="text-2xl font-bold text-cyan-300">{stats?.scannerDistribution?.length || 0}</div>
                  <div className="text-xs text-muted-foreground">Scanners</div>
                </CardContent>
              </Card>
              <Card className="border-green-500/20 bg-card/50">
                <CardContent className="p-4 text-center">
                  <div className="text-2xl font-bold text-green-300">{stats?.typeDistribution?.length || 0}</div>
                  <div className="text-xs text-muted-foreground">Obs Types</div>
                </CardContent>
              </Card>
            </div>

            {/* Distributions */}
            {stats && (stats.severityDistribution?.length > 0 || stats.scannerDistribution?.length > 0) && (
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {/* Severity Distribution */}
                {stats.severityDistribution && stats.severityDistribution.length > 0 && (
                  <Card className="border-border/50 bg-card/50">
                    <CardHeader className="pb-3">
                      <CardTitle className="text-sm">Severity Distribution</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-2">
                        {stats.severityDistribution.map((s: any) => (
                          <div key={s.severity} className="flex items-center justify-between">
                            <Badge className={`${SEVERITY_COLORS[s.severity] || SEVERITY_COLORS.info} text-xs`}>
                              {s.severity}
                            </Badge>
                            <span className="font-mono text-sm">{s.count}</span>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                )}

                {/* Scanner Distribution */}
                {stats.scannerDistribution && stats.scannerDistribution.length > 0 && (
                  <Card className="border-border/50 bg-card/50">
                    <CardHeader className="pb-3">
                      <CardTitle className="text-sm">Scanner Distribution</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-2">
                        {stats.scannerDistribution.map((s: any) => (
                          <div key={s.scanner} className="flex items-center justify-between">
                            <span className="text-sm font-mono">{s.scanner}</span>
                            <span className="font-mono text-sm text-amber-300">{s.count}</span>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                )}

                {/* Type Distribution */}
                {stats.typeDistribution && stats.typeDistribution.length > 0 && (
                  <Card className="border-border/50 bg-card/50">
                    <CardHeader className="pb-3">
                      <CardTitle className="text-sm">Type Distribution</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-2">
                        {stats.typeDistribution.map((t: any) => (
                          <div key={t.type} className="flex items-center justify-between">
                            <span className="text-sm">{TYPE_LABELS[t.type] || t.type}</span>
                            <span className="font-mono text-sm">{t.count}</span>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                )}
              </div>
            )}

            {/* Filters */}
            <Card className="border-border/50 bg-card/50">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm">Filters</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  <div>
                    <label className="text-xs text-muted-foreground">Scanner</label>
                    <select
                      className="w-full mt-1 bg-muted/30 border border-border rounded px-2 py-1.5 text-sm"
                      value={filters.scannerName || ""}
                      onChange={(e) => setFilters({ ...filters, scannerName: e.target.value || undefined, offset: 0 })}
                    >
                      <option value="">All Scanners</option>
                      <option value="nmap">Nmap</option>
                      <option value="nuclei">Nuclei</option>
                      <option value="zgrab2">ZGrab2</option>
                      <option value="web_crawler">Web Crawler</option>
                      <option value="domain_intel">Domain Intel</option>
                      <option value="vuln_scanner">Vuln Scanner</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-xs text-muted-foreground">Type</label>
                    <select
                      className="w-full mt-1 bg-muted/30 border border-border rounded px-2 py-1.5 text-sm"
                      value={filters.observationType || ""}
                      onChange={(e) => setFilters({ ...filters, observationType: e.target.value || undefined, offset: 0 })}
                    >
                      <option value="">All Types</option>
                      {Object.entries(TYPE_LABELS).map(([key, label]) => (
                        <option key={key} value={key}>{label}</option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="text-xs text-muted-foreground">Severity</label>
                    <select
                      className="w-full mt-1 bg-muted/30 border border-border rounded px-2 py-1.5 text-sm"
                      value={filters.severity || ""}
                      onChange={(e) => setFilters({ ...filters, severity: e.target.value || undefined, offset: 0 })}
                    >
                      <option value="">All Severities</option>
                      <option value="critical">Critical</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                      <option value="info">Info</option>
                    </select>
                  </div>
                  <div className="flex items-end">
                    <Button
                      variant="outline"
                      size="sm"
                      className="w-full"
                      onClick={() => setFilters({ scannerName: undefined, observationType: undefined, severity: undefined, limit: 50, offset: 0 })}
                    >
                      Clear Filters
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Observations Table */}
            <Card className="border-border/50 bg-card/50">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle className="text-lg flex items-center gap-2">
                    <Eye className="h-5 w-5 text-amber-400" />
                    Observations ({observations?.total || 0})
                  </CardTitle>
                  <div className="flex items-center gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={filters.offset === 0}
                      onClick={() => setFilters({ ...filters, offset: Math.max(0, filters.offset - filters.limit) })}
                    >
                      Previous
                    </Button>
                    <span className="text-xs text-muted-foreground">
                      {filters.offset + 1}–{Math.min(filters.offset + filters.limit, observations?.total || 0)}
                    </span>
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={(filters.offset + filters.limit) >= (observations?.total || 0)}
                      onClick={() => setFilters({ ...filters, offset: filters.offset + filters.limit })}
                    >
                      Next
                    </Button>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                {!observations?.observations?.length ? (
                  <div className="text-center py-12 text-muted-foreground">
                    <FileStack className="h-8 w-8 mx-auto mb-2 opacity-50" />
                    <p>No observations found. Run scanner ingestion to populate data.</p>
                  </div>
                ) : (
                  <div className="space-y-2">
                    {observations.observations.map((obs: any) => (
                      <div
                        key={obs.id}
                        className={`p-3 rounded border cursor-pointer transition-all ${
                          selectedObs === obs.observationId
                            ? "border-amber-500/50 bg-amber-500/10"
                            : "border-border/30 hover:border-amber-500/30"
                        }`}
                        onClick={() => setSelectedObs(obs.observationId === selectedObs ? null : obs.observationId)}
                      >
                        <div className="flex items-center justify-between mb-1">
                          <div className="flex items-center gap-2">
                            <Badge className={`${SEVERITY_COLORS[obs.severity] || SEVERITY_COLORS.info} text-xs`}>
                              {obs.severity}
                            </Badge>
                            <span className="text-sm font-mono">{obs.scannerName}</span>
                            <span className="text-xs text-muted-foreground">
                              {TYPE_LABELS[obs.observationType] || obs.observationType}
                            </span>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-mono text-muted-foreground">
                              {obs.assetHost}:{obs.assetPort}
                            </span>
                            <span className="text-xs text-muted-foreground">
                              conf: {(obs.confidence * 100).toFixed(0)}%
                            </span>
                          </div>
                        </div>
                        <p className="text-xs text-muted-foreground truncate">{obs.evidenceSummary}</p>

                        {/* Expanded detail */}
                        {selectedObs === obs.observationId && obsDetail && (
                          <div className="mt-3 p-3 bg-muted/20 rounded space-y-2 text-xs">
                            <div className="grid grid-cols-2 gap-2">
                              <div><span className="text-muted-foreground">Observation ID:</span> <span className="font-mono">{obsDetail.observationId}</span></div>
                              <div><span className="text-muted-foreground">Asset ID:</span> <span className="font-mono">{obsDetail.assetId}</span></div>
                              <div><span className="text-muted-foreground">Scanner:</span> {obsDetail.scannerName} ({obsDetail.scannerAdapter})</div>
                              <div><span className="text-muted-foreground">Mode:</span> {obsDetail.scannerMode}</div>
                              <div><span className="text-muted-foreground">Protocol:</span> {obsDetail.assetProtocol}</div>
                              <div><span className="text-muted-foreground">Policy Profile:</span> {obsDetail.policyProfile || "N/A"}</div>
                            </div>
                            {obsDetail.evidenceCve && (
                              <div><span className="text-muted-foreground">CVE:</span> <span className="text-red-300 font-mono">{obsDetail.evidenceCve}</span></div>
                            )}
                            {obsDetail.evidenceCvss && (
                              <div><span className="text-muted-foreground">CVSS:</span> <span className="text-orange-300 font-mono">{obsDetail.evidenceCvss}</span></div>
                            )}
                            <div><span className="text-muted-foreground">Evidence:</span> {obsDetail.evidenceSummary}</div>
                            <div className="text-muted-foreground">
                              Observed: {new Date(obsDetail.observedAt).toLocaleString()} | Ingested: {new Date(obsDetail.ingestedAt).toLocaleString()}
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Signals */}
            <Card className="border-purple-500/20 bg-card/50">
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <Activity className="h-5 w-5 text-purple-400" />
                  Derived Signals ({signals?.length || 0})
                </CardTitle>
                <CardDescription>
                  Intelligence signals derived from correlated observations
                </CardDescription>
              </CardHeader>
              <CardContent>
                {!signals?.length ? (
                  <div className="text-center py-8 text-muted-foreground">
                    <Activity className="h-8 w-8 mx-auto mb-2 opacity-50" />
                    <p>No signals derived yet. Ingest observations to generate signals.</p>
                  </div>
                ) : (
                  <div className="space-y-2">
                    {signals.map((sig: any) => (
                      <div key={sig.id} className="p-3 rounded border border-border/30">
                        <div className="flex items-center justify-between mb-1">
                          <div className="flex items-center gap-2">
                            <Badge className={`${SEVERITY_COLORS[sig.severity || sig.signalSeverity] || SEVERITY_COLORS.info} text-xs`}>
                              {sig.severity || sig.signalSeverity}
                            </Badge>
                            <span className="text-sm font-semibold">{sig.category}</span>
                            <Badge variant="outline" className="text-xs">{sig.signalType}</Badge>
                          </div>
                          <span className="text-xs font-mono text-muted-foreground">{sig.assetId}</span>
                        </div>
                        <p className="text-xs text-muted-foreground">{sig.rationale}</p>
                        {sig.enrichmentCve && (
                          <span className="text-xs text-red-300 font-mono">CVE: {sig.enrichmentCve}</span>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Risk Cards */}
            <Card className="border-red-500/20 bg-card/50">
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <Shield className="h-5 w-5 text-red-400" />
                  Risk Cards ({riskCards?.length || 0})
                </CardTitle>
                <CardDescription>
                  Composite risk scores using hybrid CVSS × CARVER+SHOCK × BIA formula
                </CardDescription>
              </CardHeader>
              <CardContent>
                {!riskCards?.length ? (
                  <div className="text-center py-8 text-muted-foreground">
                    <Shield className="h-8 w-8 mx-auto mb-2 opacity-50" />
                    <p>No risk cards generated yet. Ingest observations to generate risk assessments.</p>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {riskCards.map((card: any) => (
                      <div key={card.id} className="p-4 rounded-lg border border-border/30 bg-muted/10">
                        <div className="flex items-center justify-between mb-2">
                          <span className="font-mono text-sm">{card.assetId}</span>
                          <div className={`text-2xl font-bold ${
                            card.finalScore >= 8 ? "text-red-400" :
                            card.finalScore >= 6 ? "text-orange-400" :
                            card.finalScore >= 4 ? "text-yellow-400" :
                            "text-green-400"
                          }`}>
                            {card.finalScore.toFixed(1)}/10
                          </div>
                        </div>
                        <p className="text-sm text-muted-foreground mb-3">{card.summary}</p>
                        <div className="grid grid-cols-4 gap-2 text-xs">
                          <div className="p-2 bg-muted/20 rounded text-center">
                            <div className="font-bold">{card.componentCvss?.toFixed(1)}</div>
                            <div className="text-muted-foreground">CVSS</div>
                          </div>
                          <div className="p-2 bg-muted/20 rounded text-center">
                            <div className="font-bold">{card.componentCarver?.toFixed(1)}</div>
                            <div className="text-muted-foreground">CARVER</div>
                          </div>
                          <div className="p-2 bg-muted/20 rounded text-center">
                            <div className="font-bold">{card.componentBia?.toFixed(1)}</div>
                            <div className="text-muted-foreground">BIA</div>
                          </div>
                          <div className="p-2 bg-muted/20 rounded text-center">
                            <div className="font-bold">{(card.confidenceWeight * 100).toFixed(0)}%</div>
                            <div className="text-muted-foreground">Confidence</div>
                          </div>
                        </div>
                        {card.whyItMatters && (
                          <p className="text-xs text-muted-foreground mt-2 italic">{card.whyItMatters}</p>
                        )}
                        {card.recommendations && card.recommendations.length > 0 && (
                          <div className="mt-2 space-y-1">
                            <div className="text-xs font-semibold text-amber-300">Recommendations:</div>
                            {(card.recommendations as string[]).slice(0, 3).map((rec: string, i: number) => (
                              <div key={i} className="text-xs text-muted-foreground flex items-start gap-1">
                                <span className="text-amber-400">•</span> {rec}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </>
        )}
      </div>
    </AppShell>
  );
}
