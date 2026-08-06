import { useState, useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { useToast } from "@/hooks/use-toast";
import { trpc } from "@/lib/trpc";
import {
  Globe, Building2, ShieldCheck, Lock, Search, FileKey, Network,
  ChevronDown, ChevronUp, Info, Fingerprint, Radar, Loader2,
  CheckCircle2, XCircle, Clock, ExternalLink, AlertTriangle
} from "lucide-react";

interface AffiliatedDomain {
  domain: string;
  relationship: string;
  confidence: number;
  source: string;
  evidence: string;
  registrantOrg?: string;
  registrantEmail?: string;
}

interface AffiliatedDomainResult {
  targetDomain: string;
  searchedAt: number;
  registrantOrg: string | null;
  registrantEmail: string | null;
  affiliatedDomains: AffiliatedDomain[];
  totalDiscovered: number;
  sourceBreakdown: Record<string, number>;
  summary: string;
}

const relationshipConfig: Record<string, { label: string; icon: React.ReactNode; color: string }> = {
  same_registrant: { label: "Same Registrant", icon: <Building2 className="h-3 w-3" />, color: "text-purple-400 bg-purple-500/10 border-purple-500/30" },
  same_org: { label: "Same Organization", icon: <Building2 className="h-3 w-3" />, color: "text-blue-400 bg-blue-500/10 border-blue-500/30" },
  shared_certificate: { label: "Shared Certificate", icon: <Lock className="h-3 w-3" />, color: "text-cyan-400 bg-cyan-500/10 border-cyan-500/30" },
  dns_correlation: { label: "DNS Correlation", icon: <Network className="h-3 w-3" />, color: "text-amber-400 bg-amber-500/10 border-amber-500/30" },
  llm_knowledge: { label: "Known Affiliation", icon: <Search className="h-3 w-3" />, color: "text-emerald-400 bg-emerald-500/10 border-emerald-500/30" },
  spf_include: { label: "SPF Include", icon: <FileKey className="h-3 w-3" />, color: "text-orange-400 bg-orange-500/10 border-orange-500/30" },
};

const sourceConfig: Record<string, { label: string; color: string }> = {
  securitytrails_reverse_whois: { label: "SecurityTrails WHOIS", color: "text-purple-400" },
  securitytrails_associated: { label: "SecurityTrails Associated", color: "text-blue-400" },
  crtsh_org_search: { label: "crt.sh CT Logs", color: "text-cyan-400" },
  dns_spf: { label: "DNS SPF Analysis", color: "text-amber-400" },
  dns_dmarc: { label: "DNS DMARC Analysis", color: "text-orange-400" },
  llm_knowledge: { label: "Intelligence Knowledge", color: "text-emerald-400" },
};

function ConfidenceBadge({ confidence }: { confidence: number }) {
  let color = "text-slate-400 bg-slate-500/10 border-slate-500/30";
  let label = "Low";
  if (confidence >= 80) { color = "text-emerald-400 bg-emerald-500/10 border-emerald-500/30"; label = "High"; }
  else if (confidence >= 50) { color = "text-amber-400 bg-amber-500/10 border-amber-500/30"; label = "Medium"; }

  return (
    <Badge variant="outline" className={`text-[10px] font-mono ${color}`}>
      {label} ({confidence}%)
    </Badge>
  );
}

function ScanStatusBadge({ status }: { status: string }) {
  switch (status) {
    case 'scan_complete':
    case 'completed':
      return <Badge variant="outline" className="text-[10px] text-emerald-400 bg-emerald-500/10 border-emerald-500/30"><CheckCircle2 className="h-3 w-3 mr-1" />Scanned</Badge>;
    case 'discovering':
    case 'enriching':
    case 'analyzing':
    case 'scoring':
      return <Badge variant="outline" className="text-[10px] text-cyan-400 bg-cyan-500/10 border-cyan-500/30 animate-pulse"><Loader2 className="h-3 w-3 mr-1 animate-spin" />{status}</Badge>;
    case 'failed':
    case 'error':
      return <Badge variant="outline" className="text-[10px] text-red-400 bg-red-500/10 border-red-500/30"><XCircle className="h-3 w-3 mr-1" />Failed</Badge>;
    case 'queued':
      return <Badge variant="outline" className="text-[10px] text-amber-400 bg-amber-500/10 border-amber-500/30"><Clock className="h-3 w-3 mr-1" />Queued</Badge>;
    default:
      return <Badge variant="outline" className="text-[10px] text-slate-400 bg-slate-500/10 border-slate-500/30">Not Scanned</Badge>;
  }
}

export default function AffiliatedDomainsTab({
  affiliatedDomains,
  scanId,
}: {
  affiliatedDomains: AffiliatedDomainResult | null | undefined;
  scanId: number;
}) {
  const [filterSource, setFilterSource] = useState<string>("all");
  const [showAll, setShowAll] = useState(false);
  const [selectedDomains, setSelectedDomains] = useState<Set<string>>(new Set());
  const { toast } = useToast();

  // Fetch affiliated domain scan statuses
  const { data: affiliatedScans, refetch: refetchScans } = trpc.domainIntel.getAffiliatedDomainScans.useQuery(
    { parentScanId: scanId },
    { refetchInterval: 10000 } // Poll every 10s for status updates
  );

  // Scan mutation
  const scanMutation = trpc.domainIntel.scanAffiliatedDomains.useMutation({
    onSuccess: (data) => {
      toast({
        title: "Affiliated Domain Scans Queued",
        description: `${data.totalQueued} scan(s) queued, ${data.totalSkipped} already running, ${data.totalFailed} failed`,
      });
      refetchScans();
      setSelectedDomains(new Set());
    },
    onError: (err) => {
      toast({
        title: "Failed to Queue Scans",
        description: err.message,
        variant: "destructive",
      });
    },
  });

  // Build scan status map: domain → status
  const scanStatusMap = useMemo(() => {
    const map = new Map<string, { status: string; scanId: number; riskScore: number | null; riskBand: string | null; assets: number | null }>();
    if (affiliatedScans) {
      for (const s of affiliatedScans) {
        map.set(s.domain, {
          status: s.status || 'unknown',
          scanId: s.scanId,
          riskScore: s.overallRiskScore,
          riskBand: s.overallRiskBand,
          assets: s.totalAssets,
        });
      }
    }
    return map;
  }, [affiliatedScans]);

  if (!affiliatedDomains) {
    return (
      <Card className="border-border/50">
        <CardContent className="p-8 text-center">
          <Globe className="h-12 w-12 text-muted-foreground mx-auto mb-4 opacity-50" />
          <h3 className="text-lg font-semibold mb-2">Affiliated Domain Discovery Not Available</h3>
          <p className="text-sm text-muted-foreground max-w-md mx-auto">
            Affiliated domain discovery was not run for this scan. Re-run the scan to discover domains owned by the same organization using reverse WHOIS, certificate transparency, and DNS correlation.
          </p>
        </CardContent>
      </Card>
    );
  }

  const domains = affiliatedDomains.affiliatedDomains || [];

  const filtered = useMemo(() => {
    if (filterSource === "all") return domains;
    return domains.filter(d => d.source === filterSource);
  }, [domains, filterSource]);

  const displayed = showAll ? filtered : filtered.slice(0, 25);

  const sourceKeys = useMemo(() => {
    return Object.keys(affiliatedDomains.sourceBreakdown || {});
  }, [affiliatedDomains]);

  const highConfCount = domains.filter(d => d.confidence >= 80).length;
  const medConfCount = domains.filter(d => d.confidence >= 50 && d.confidence < 80).length;
  const lowConfCount = domains.filter(d => d.confidence < 50).length;

  // Domains eligible for scanning (not already scanned or in progress)
  const scannableDomains = useMemo(() => {
    return domains.filter(d => {
      const scanInfo = scanStatusMap.get(d.domain);
      return !scanInfo || scanInfo.status === 'failed' || scanInfo.status === 'error';
    }).map(d => d.domain);
  }, [domains, scanStatusMap]);

  const handleSelectAll = () => {
    if (selectedDomains.size === scannableDomains.length) {
      setSelectedDomains(new Set());
    } else {
      setSelectedDomains(new Set(scannableDomains));
    }
  };

  const handleToggleDomain = (domain: string) => {
    const next = new Set(selectedDomains);
    if (next.has(domain)) next.delete(domain);
    else next.add(domain);
    setSelectedDomains(next);
  };

  const handleScanSelected = () => {
    if (selectedDomains.size === 0) return;
    scanMutation.mutate({
      parentScanId: scanId,
      domains: Array.from(selectedDomains),
      scanMode: 'standard',
    });
  };

  const handleScanAll = () => {
    if (scannableDomains.length === 0) {
      toast({ title: "All domains already scanned", description: "All affiliated domains have been scanned or are currently in progress." });
      return;
    }
    // Limit to 20 at a time to avoid overwhelming the system
    const batch = scannableDomains.slice(0, 20);
    scanMutation.mutate({
      parentScanId: scanId,
      domains: batch,
      scanMode: 'standard',
    });
  };

  const scanningCount = affiliatedScans?.filter(s => ['discovering', 'enriching', 'analyzing', 'scoring'].includes(s.status || '')).length || 0;
  const completedCount = affiliatedScans?.filter(s => s.status === 'scan_complete' || s.status === 'completed').length || 0;

  return (
    <div className="space-y-4">
      {/* Page Description */}
      <p className="text-sm text-muted-foreground">
        Domains owned by or affiliated with the target organization, discovered through reverse WHOIS lookups, certificate transparency logs, DNS correlation, and intelligence knowledge. These represent the organization's broader attack surface.
      </p>

      {/* Registrant Info */}
      {(affiliatedDomains.registrantOrg || affiliatedDomains.registrantEmail) && (
        <Card className="border-purple-500/30 bg-purple-500/5">
          <CardContent className="p-4">
            <div className="flex items-center gap-3 flex-wrap">
              <Building2 className="h-4 w-4 text-purple-400 shrink-0" />
              <div className="space-y-1">
                {affiliatedDomains.registrantOrg && (
                  <div className="text-sm">
                    <span className="text-muted-foreground">Registrant Organization:</span>{" "}
                    <span className="font-semibold text-purple-400">{affiliatedDomains.registrantOrg}</span>
                  </div>
                )}
                {affiliatedDomains.registrantEmail && (
                  <div className="text-sm">
                    <span className="text-muted-foreground">Registrant Email:</span>{" "}
                    <span className="font-mono text-xs">{affiliatedDomains.registrantEmail}</span>
                  </div>
                )}
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <Card className="border-cyan-500/30 bg-cyan-500/5">
          <CardContent className="p-4 text-center">
            <p className="text-3xl font-bold text-cyan-400">{affiliatedDomains.totalDiscovered}</p>
            <p className="text-xs text-muted-foreground mt-1">Total Affiliated</p>
          </CardContent>
        </Card>
        <Card className="border-emerald-500/30 bg-emerald-500/5">
          <CardContent className="p-4 text-center">
            <p className="text-3xl font-bold text-emerald-400">{highConfCount}</p>
            <p className="text-xs text-muted-foreground mt-1">High Confidence</p>
          </CardContent>
        </Card>
        <Card className="border-amber-500/30 bg-amber-500/5">
          <CardContent className="p-4 text-center">
            <p className="text-3xl font-bold text-amber-400">{medConfCount}</p>
            <p className="text-xs text-muted-foreground mt-1">Medium Confidence</p>
          </CardContent>
        </Card>
        <Card className="border-slate-500/30 bg-slate-500/5">
          <CardContent className="p-4 text-center">
            <p className="text-3xl font-bold text-slate-400">{lowConfCount}</p>
            <p className="text-xs text-muted-foreground mt-1">Low Confidence</p>
          </CardContent>
        </Card>
        <Card className="border-blue-500/30 bg-blue-500/5">
          <CardContent className="p-4 text-center">
            <p className="text-3xl font-bold text-blue-400">{completedCount}</p>
            <p className="text-xs text-muted-foreground mt-1">Scanned</p>
          </CardContent>
        </Card>
      </div>

      {/* Scan Actions Bar */}
      <Card className="border-border/50 bg-muted/10">
        <CardContent className="p-3">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div className="flex items-center gap-3">
              <Radar className="h-4 w-4 text-cyan-400" />
              <span className="text-sm font-semibold">Attack Surface Expansion</span>
              {scanningCount > 0 && (
                <Badge variant="outline" className="text-[10px] text-cyan-400 bg-cyan-500/10 border-cyan-500/30 animate-pulse">
                  <Loader2 className="h-3 w-3 mr-1 animate-spin" />
                  {scanningCount} scanning
                </Badge>
              )}
              {completedCount > 0 && (
                <Badge variant="outline" className="text-[10px] text-emerald-400 bg-emerald-500/10 border-emerald-500/30">
                  <CheckCircle2 className="h-3 w-3 mr-1" />
                  {completedCount} complete
                </Badge>
              )}
            </div>
            <div className="flex items-center gap-2">
              {selectedDomains.size > 0 && (
                <Button
                  size="sm"
                  variant="outline"
                  className="h-7 text-xs border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/10"
                  onClick={handleScanSelected}
                  disabled={scanMutation.isPending}
                >
                  {scanMutation.isPending ? <Loader2 className="h-3 w-3 mr-1 animate-spin" /> : <Radar className="h-3 w-3 mr-1" />}
                  Scan Selected ({selectedDomains.size})
                </Button>
              )}
              <Button
                size="sm"
                className="h-7 text-xs bg-cyan-600 hover:bg-cyan-700 text-white"
                onClick={handleScanAll}
                disabled={scanMutation.isPending || scannableDomains.length === 0}
              >
                {scanMutation.isPending ? <Loader2 className="h-3 w-3 mr-1 animate-spin" /> : <Radar className="h-3 w-3 mr-1" />}
                Scan All ({scannableDomains.length})
              </Button>
            </div>
          </div>
          {scannableDomains.length === 0 && domains.length > 0 && (
            <p className="text-[10px] text-muted-foreground mt-2 flex items-center gap-1">
              <CheckCircle2 className="h-3 w-3 text-emerald-400" />
              All affiliated domains have been scanned or are currently in progress.
            </p>
          )}
          {domains.length > 20 && scannableDomains.length > 20 && (
            <p className="text-[10px] text-amber-400 mt-2 flex items-center gap-1">
              <AlertTriangle className="h-3 w-3" />
              "Scan All" will queue the first 20 domains. Select specific domains for targeted scanning.
            </p>
          )}
        </CardContent>
      </Card>

      {/* Summary */}
      {affiliatedDomains.summary && (
        <Card className="border-border/50">
          <CardContent className="p-4">
            <div className="flex items-start gap-3">
              <Info className="h-4 w-4 text-cyan-400 mt-0.5 shrink-0" />
              <p className="text-sm text-foreground/80 leading-relaxed">{affiliatedDomains.summary}</p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Source Filters */}
      {sourceKeys.length > 0 && (
        <div className="flex items-center gap-3 flex-wrap">
          <span className="text-xs text-muted-foreground font-semibold uppercase tracking-wider">Source:</span>
          <div className="flex gap-1.5 flex-wrap">
            <Button
              variant={filterSource === "all" ? "default" : "outline"}
              size="sm"
              className="h-6 text-[10px] px-2"
              onClick={() => setFilterSource("all")}
            >
              All ({domains.length})
            </Button>
            {sourceKeys.map(src => (
              <Button
                key={src}
                variant={filterSource === src ? "default" : "outline"}
                size="sm"
                className="h-6 text-[10px] px-2"
                onClick={() => setFilterSource(src)}
              >
                {sourceConfig[src]?.label || src} ({affiliatedDomains.sourceBreakdown[src]})
              </Button>
            ))}
          </div>
        </div>
      )}

      {/* Domain List */}
      {displayed.length > 0 ? (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border/50">
                <th className="text-left py-2 px-2 w-8">
                  <Checkbox
                    checked={selectedDomains.size === scannableDomains.length && scannableDomains.length > 0}
                    onCheckedChange={handleSelectAll}
                  />
                </th>
                <th className="text-left py-2 px-3 text-xs font-semibold text-muted-foreground">Domain</th>
                <th className="text-left py-2 px-3 text-xs font-semibold text-muted-foreground">Relationship</th>
                <th className="text-left py-2 px-3 text-xs font-semibold text-muted-foreground">Confidence</th>
                <th className="text-left py-2 px-3 text-xs font-semibold text-muted-foreground">Source</th>
                <th className="text-left py-2 px-3 text-xs font-semibold text-muted-foreground">Scan Status</th>
                <th className="text-left py-2 px-3 text-xs font-semibold text-muted-foreground">Risk</th>
              </tr>
            </thead>
            <tbody>
              {displayed.map((d, i) => {
                const rel = relationshipConfig[d.relationship] || relationshipConfig.same_org;
                const scanInfo = scanStatusMap.get(d.domain);
                const isScannable = !scanInfo || scanInfo.status === 'failed' || scanInfo.status === 'error';
                const isSelected = selectedDomains.has(d.domain);

                return (
                  <tr key={i} className={`border-b border-border/30 hover:bg-muted/20 ${isSelected ? 'bg-cyan-500/5' : ''}`}>
                    <td className="py-2 px-2">
                      <Checkbox
                        checked={isSelected}
                        onCheckedChange={() => handleToggleDomain(d.domain)}
                        disabled={!isScannable}
                      />
                    </td>
                    <td className="py-2 px-3">
                      <div className="flex items-center gap-2">
                        <Globe className="h-3 w-3 text-muted-foreground shrink-0" />
                        <span className="font-mono text-xs font-medium text-cyan-400">{d.domain}</span>
                        {scanInfo?.scanId && (scanInfo.status === 'scan_complete' || scanInfo.status === 'completed') && (
                          <a href={`/domain-intel/results/${scanInfo.scanId}`} className="text-muted-foreground hover:text-cyan-400">
                            <ExternalLink className="h-3 w-3" />
                          </a>
                        )}
                      </div>
                    </td>
                    <td className="py-2 px-3">
                      <Badge variant="outline" className={`text-[10px] font-mono ${rel.color}`}>
                        {rel.icon}
                        <span className="ml-1">{rel.label}</span>
                      </Badge>
                    </td>
                    <td className="py-2 px-3">
                      <ConfidenceBadge confidence={d.confidence} />
                    </td>
                    <td className="py-2 px-3">
                      <span className={`text-xs ${sourceConfig[d.source]?.color || 'text-muted-foreground'}`}>
                        {sourceConfig[d.source]?.label || d.source}
                      </span>
                    </td>
                    <td className="py-2 px-3">
                      <ScanStatusBadge status={scanInfo?.status || 'not_scanned'} />
                    </td>
                    <td className="py-2 px-3">
                      {scanInfo?.riskScore != null ? (
                        <Badge
                          variant="outline"
                          className={`text-[10px] font-mono ${
                            scanInfo.riskBand === 'critical' ? 'text-red-400 bg-red-500/10 border-red-500/30' :
                            scanInfo.riskBand === 'high' ? 'text-orange-400 bg-orange-500/10 border-orange-500/30' :
                            scanInfo.riskBand === 'medium' ? 'text-amber-400 bg-amber-500/10 border-amber-500/30' :
                            'text-emerald-400 bg-emerald-500/10 border-emerald-500/30'
                          }`}
                        >
                          {scanInfo.riskScore} ({scanInfo.riskBand})
                        </Badge>
                      ) : (
                        <span className="text-xs text-muted-foreground">—</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <Card className="border-emerald-500/30 bg-emerald-500/5">
          <CardContent className="p-6 text-center">
            <ShieldCheck className="h-8 w-8 text-emerald-400 mx-auto mb-3" />
            <h3 className="text-sm font-semibold text-emerald-400">No Affiliated Domains Found</h3>
            <p className="text-xs text-muted-foreground mt-1 max-w-md mx-auto">
              No additional domains were discovered for this organization. The registrant may use privacy-protected WHOIS or operate under a single domain.
            </p>
          </CardContent>
        </Card>
      )}

      {/* Show More / Less */}
      {filtered.length > 25 && (
        <div className="text-center">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setShowAll(!showAll)}
            className="text-xs"
          >
            {showAll ? (
              <>Show Less <ChevronUp className="h-3 w-3 ml-1" /></>
            ) : (
              <>Show All {filtered.length} Domains <ChevronDown className="h-3 w-3 ml-1" /></>
            )}
          </Button>
        </div>
      )}

      {/* Affiliated Scan Results Summary */}
      {affiliatedScans && affiliatedScans.length > 0 && (
        <Card className="border-border/50">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Radar className="h-4 w-4 text-cyan-400" />
              Affiliated Domain Scan Results
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-0">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border/50">
                    <th className="text-left py-2 px-3 text-xs font-semibold text-muted-foreground">Domain</th>
                    <th className="text-left py-2 px-3 text-xs font-semibold text-muted-foreground">Status</th>
                    <th className="text-left py-2 px-3 text-xs font-semibold text-muted-foreground">Risk Score</th>
                    <th className="text-left py-2 px-3 text-xs font-semibold text-muted-foreground">Assets</th>
                    <th className="text-left py-2 px-3 text-xs font-semibold text-muted-foreground">Findings</th>
                    <th className="text-left py-2 px-3 text-xs font-semibold text-muted-foreground">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {affiliatedScans.map((s) => (
                    <tr key={s.scanId} className="border-b border-border/30 hover:bg-muted/20">
                      <td className="py-2 px-3">
                        <span className="font-mono text-xs text-cyan-400">{s.domain}</span>
                      </td>
                      <td className="py-2 px-3">
                        <ScanStatusBadge status={s.status || 'unknown'} />
                      </td>
                      <td className="py-2 px-3">
                        {s.overallRiskScore != null ? (
                          <Badge
                            variant="outline"
                            className={`text-[10px] font-mono ${
                              s.overallRiskBand === 'critical' ? 'text-red-400 bg-red-500/10 border-red-500/30' :
                              s.overallRiskBand === 'high' ? 'text-orange-400 bg-orange-500/10 border-orange-500/30' :
                              s.overallRiskBand === 'medium' ? 'text-amber-400 bg-amber-500/10 border-amber-500/30' :
                              'text-emerald-400 bg-emerald-500/10 border-emerald-500/30'
                            }`}
                          >
                            {s.overallRiskScore} ({s.overallRiskBand})
                          </Badge>
                        ) : <span className="text-xs text-muted-foreground">—</span>}
                      </td>
                      <td className="py-2 px-3 text-xs font-mono">{s.totalAssets ?? '—'}</td>
                      <td className="py-2 px-3 text-xs font-mono">{s.totalFindings ?? '—'}</td>
                      <td className="py-2 px-3">
                        {(s.status === 'scan_complete' || s.status === 'completed') && (
                          <a href={`/domain-intel/results/${s.scanId}`}>
                            <Button variant="outline" size="sm" className="h-6 text-[10px] px-2">
                              <ExternalLink className="h-3 w-3 mr-1" />View
                            </Button>
                          </a>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Source Breakdown */}
      {Object.keys(affiliatedDomains.sourceBreakdown || {}).length > 1 && (
        <Card className="border-border/50">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Fingerprint className="h-4 w-4 text-purple-400" />
              Discovery Source Breakdown
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-0">
            <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
              {Object.entries(affiliatedDomains.sourceBreakdown).map(([src, count]) => (
                <div key={src} className="flex items-center justify-between p-2 rounded bg-muted/20">
                  <span className={`text-xs ${sourceConfig[src]?.color || 'text-muted-foreground'}`}>
                    {sourceConfig[src]?.label || src}
                  </span>
                  <span className="text-xs font-mono font-bold">{count}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Metadata */}
      <div className="text-[10px] text-muted-foreground text-right">
        Searched at {new Date(affiliatedDomains.searchedAt).toLocaleString()} — {affiliatedDomains.totalDiscovered} affiliated domains discovered
      </div>
    </div>
  );
}
