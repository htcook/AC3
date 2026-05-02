import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Progress } from "@/components/ui/progress";
import {
  ShieldAlert, ShieldCheck, ShieldX, AlertTriangle, ChevronDown, ChevronUp,
  Loader2, Server, Globe, Network, Lock, Mail, Cloud, Building2,
  Info, ExternalLink, Bug, FileText, Users, TrendingUp, TrendingDown, Minus, CheckCircle2,
  XCircle, Clock, Shield, Layers, TriangleAlert, Scale, Handshake, Activity
} from "lucide-react";
import { createAssetOwnershipFilter, type AssetOwnershipFilter } from "../../../../shared/managed-provider-filter";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-red-400 bg-red-500/20 border-red-500/40",
  high: "text-orange-400 bg-orange-500/20 border-orange-500/40",
  medium: "text-yellow-400 bg-yellow-500/20 border-yellow-500/40",
  low: "text-blue-400 bg-blue-500/20 border-blue-500/40",
  minimal: "text-slate-400 bg-slate-500/20 border-slate-500/40",
};

const RISK_BAND_COLORS: Record<string, string> = {
  CRITICAL: "bg-red-500",
  HIGH: "bg-orange-500",
  MEDIUM: "bg-yellow-500",
  LOW: "bg-emerald-500",
  MINIMAL: "bg-slate-500",
};

interface VendorRiskTabProps {
  scanId: number;
  domain: string;
  pipeline: any;
  assets: any[];
}

// Mini sparkline component for vendor risk score history
function VendorRiskSparkline({ history }: { history: { vendorRiskScore: number; date: string }[] }) {
  if (history.length < 2) return null;
  const scores = history.map(h => h.vendorRiskScore);
  const max = Math.max(...scores, 100);
  const min = Math.min(...scores, 0);
  const range = max - min || 1;
  const width = 120;
  const height = 32;
  const padding = 2;
  const points = scores.map((s, i) => {
    const x = padding + (i / (scores.length - 1)) * (width - padding * 2);
    const y = height - padding - ((s - min) / range) * (height - padding * 2);
    return `${x},${y}`;
  });
  const lastScore = scores[scores.length - 1];
  const color = lastScore >= 60 ? '#ef4444' : lastScore >= 40 ? '#f59e0b' : lastScore >= 20 ? '#3b82f6' : '#10b981';
  return (
    <svg width={width} height={height} className="opacity-70">
      <polyline
        points={points.join(' ')}
        fill="none"
        stroke={color}
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      {scores.map((s, i) => {
        const x = padding + (i / (scores.length - 1)) * (width - padding * 2);
        const y = height - padding - ((s - min) / range) * (height - padding * 2);
        return <circle key={i} cx={x} cy={y} r={i === scores.length - 1 ? 3 : 1.5} fill={color} />;
      })}
    </svg>
  );
}

export default function VendorRiskTab({ scanId, domain, pipeline, assets }: VendorRiskTabProps) {
  const [expandedVendorCves, setExpandedVendorCves] = useState(false);
  const [expandedConcentration, setExpandedConcentration] = useState(true);
  const [expandedRecommendations, setExpandedRecommendations] = useState(true);
  const [expandedSharedResp, setExpandedSharedResp] = useState(false);
  const [expandedHistory, setExpandedHistory] = useState(false);

  // Fetch infrastructure map for vendor dependencies and supply chain risks
  const { data: infraMap, isLoading: infraLoading } = trpc.calderaProxy.inferInfrastructure.useQuery(
    { scanId },
    { staleTime: 5 * 60 * 1000 }
  );

  // Fetch vendor risk history for trend indicators
  const { data: riskHistory } = trpc.calderaProxy.getVendorRiskHistory.useQuery(
    { scanId, domain },
    { staleTime: 5 * 60 * 1000 }
  );

  // Extract managed provider info from pipeline
  const emailSecReport = pipeline?.emailSecurity || pipeline?.emailSecurityReport || null;
  const managedProvider = emailSecReport?.managedProvider || null;
  const mxProvider = emailSecReport?.mx?.provider || null;
  const providerName = managedProvider?.name || mxProvider || null;

  // Build ownership filter to partition assets
  const ownershipFilter = useMemo(() => {
    return createAssetOwnershipFilter({
      managedProviderName: providerName,
      primaryDomain: domain,
    });
  }, [providerName, domain]);

  // Partition assets into client-owned vs managed/third-party
  const { clientOwned, managed } = useMemo(() => {
    const clientOwned: any[] = [];
    const managed: any[] = [];
    for (const asset of assets) {
      if (ownershipFilter.isClientOwned({ hostname: asset.hostname || '', tags: asset.tags || [] })) {
        clientOwned.push(asset);
      } else {
        managed.push(asset);
      }
    }
    return { clientOwned, managed };
  }, [assets, ownershipFilter]);

  // Extract vendor-managed CVEs from pipeline observations
  const vendorCves = useMemo(() => {
    const allObs = pipeline?.passiveRecon?.allObservations || [];
    const connectorResults = pipeline?.passiveRecon?.connectorResults || [];
    const cves: any[] = [];
    const seen = new Set<string>();

    // Check all observations for CVEs on managed provider hosts
    const managedHostnames = new Set(managed.map((a: any) => (a.hostname || '').toLowerCase()));

    for (const cr of connectorResults) {
      if (!cr.observations) continue;
      for (const obs of cr.observations) {
        const ev = obs.evidence || {};
        const cveId = ev.cve_id || ev.cveId;
        if (!cveId || seen.has(cveId)) continue;
        const hostname = (ev.hostname || obs.assetHostname || '').toLowerCase();
        if (managedHostnames.has(hostname) || ev.providerManagedOnly) {
          seen.add(cveId);
          cves.push({
            cveId,
            hostname,
            cvss: ev.cvss || ev.cvssScore || ev.cvss_score || null,
            severity: ev.severity || (ev.cvss >= 9 ? 'critical' : ev.cvss >= 7 ? 'high' : ev.cvss >= 4 ? 'medium' : 'low'),
            description: ev.description || ev.cve_description || '',
            kevListed: ev.kevListed || ev.kev_listed || false,
            product: ev.product || ev.technology || '',
            version: ev.version || '',
            connector: cr.connector,
          });
        }
      }
    }

    // Sort by CVSS descending
    cves.sort((a, b) => (b.cvss || 0) - (a.cvss || 0));
    return cves;
  }, [pipeline, managed]);

  // Compute vendor risk score (same algorithm as PDF export)
  const vendorRiskMetrics = useMemo(() => {
    const critical = vendorCves.filter(c => c.severity === 'critical' || (c.cvss && c.cvss >= 9)).length;
    const high = vendorCves.filter(c => c.severity === 'high' || (c.cvss && c.cvss >= 7 && c.cvss < 9)).length;
    const medium = vendorCves.filter(c => c.severity === 'medium' || (c.cvss && c.cvss >= 4 && c.cvss < 7)).length;
    const low = vendorCves.filter(c => c.severity === 'low' || (c.cvss && c.cvss < 4)).length;
    const kev = vendorCves.filter(c => c.kevListed).length;

    const score = Math.min(100, Math.round(
      (critical * 25 + high * 15 + medium * 8 + low * 3 + kev * 10) /
      Math.max(1, vendorCves.length) * 10
    ));
    const band = score >= 80 ? 'CRITICAL' : score >= 60 ? 'HIGH' : score >= 40 ? 'MEDIUM' : score >= 20 ? 'LOW' : 'MINIMAL';

    return { score, band, critical, high, medium, low, kev, total: vendorCves.length };
  }, [vendorCves]);

  // Extract supply chain risks and vendor dependencies from infra map
  const supplyChainRisks = infraMap?.supplyChainRisks || [];
  const vendorDependencies = infraMap?.vendorDependencies || [];

  // Build shared responsibility model
  const sharedResponsibility = useMemo(() => {
    if (!providerName) return null;

    const KNOWN_PROVIDERS: Record<string, { providerScope: string[]; customerScope: string[]; sharedScope: string[] }> = {
      'Microsoft 365': {
        providerScope: ['Exchange Online server patching', 'Infrastructure security', 'Physical datacenter security', 'Platform availability (SLA)', 'Anti-malware engine updates'],
        customerScope: ['SPF/DKIM/DMARC configuration', 'Tenant security settings', 'Conditional Access policies', 'User access management', 'Data classification & DLP rules', 'Mailbox audit log review'],
        sharedScope: ['Incident response coordination', 'Threat intelligence sharing', 'Compliance reporting'],
      },
      'Google Workspace': {
        providerScope: ['Gmail server infrastructure', 'Infrastructure security', 'Physical datacenter security', 'Platform availability (SLA)', 'Spam/phishing filter updates'],
        customerScope: ['SPF/DKIM/DMARC configuration', 'Workspace admin console settings', 'User access management', 'Data Loss Prevention rules', 'Security investigation tool usage'],
        sharedScope: ['Incident response coordination', 'Threat intelligence sharing', 'Compliance reporting'],
      },
      'Cloudflare': {
        providerScope: ['CDN/WAF infrastructure', 'DDoS mitigation', 'Edge network availability', 'SSL/TLS certificate management (if using CF certs)', 'Bot management engine'],
        customerScope: ['WAF rule configuration', 'Page rules & caching policies', 'DNS record management', 'Origin server security', 'Rate limiting configuration'],
        sharedScope: ['Incident response coordination', 'Security event monitoring', 'Custom rule tuning'],
      },
      'AWS': {
        providerScope: ['Physical infrastructure security', 'Hypervisor & network infrastructure', 'Managed service patching (RDS, Lambda, etc.)', 'Global infrastructure availability'],
        customerScope: ['IAM policies & access control', 'Security group configuration', 'Data encryption configuration', 'Application security', 'OS patching (EC2)', 'Network ACLs & VPC design'],
        sharedScope: ['Incident response coordination', 'Compliance framework alignment', 'Shared vulnerability disclosure'],
      },
    };

    // Try exact match first, then partial
    const match = KNOWN_PROVIDERS[providerName] ||
      Object.entries(KNOWN_PROVIDERS).find(([k]) => providerName.toLowerCase().includes(k.toLowerCase()))?.[1];

    if (match) return { provider: providerName, ...match };

    // Generic fallback
    return {
      provider: providerName,
      providerScope: ['Infrastructure security', 'Platform patching', 'Physical security', 'Service availability'],
      customerScope: ['Configuration management', 'Access control', 'Data protection', 'Compliance monitoring'],
      sharedScope: ['Incident response', 'Security monitoring', 'Compliance reporting'],
    };
  }, [providerName]);

  // Build recommendations
  const recommendations = useMemo(() => {
    const recs: { priority: 'critical' | 'high' | 'medium' | 'low'; title: string; description: string }[] = [];

    if (vendorRiskMetrics.kev > 0) {
      recs.push({
        priority: 'critical',
        title: `Escalate ${vendorRiskMetrics.kev} CISA KEV-listed CVE(s) with ${providerName || 'provider'}`,
        description: `These CVEs have known active exploitation in the wild. Verify provider patch timeline and request written confirmation of remediation.`,
      });
    }

    if (vendorRiskMetrics.critical > 0) {
      recs.push({
        priority: 'high',
        title: `Review ${vendorRiskMetrics.critical} critical-severity CVE(s) on provider infrastructure`,
        description: `Critical CVEs on managed infrastructure represent supply chain risk. Verify provider SLA for critical patch response time.`,
      });
    }

    // Vendor concentration risk
    const topVendor = vendorDependencies[0];
    if (topVendor && topVendor.serviceCount >= 3) {
      recs.push({
        priority: 'high',
        title: `Address vendor concentration: ${topVendor.vendor} provides ${topVendor.serviceCount} services`,
        description: `Single vendor failure could cascade across ${topVendor.services.join(', ')}. Evaluate redundancy for critical services.`,
      });
    }

    if (providerName) {
      recs.push({
        priority: 'medium',
        title: `Verify ${providerName} SOC 2 Type II or equivalent certification`,
        description: `Request current compliance attestation. Ensure contractual right-to-audit and breach notification clauses are current.`,
      });
      recs.push({
        priority: 'medium',
        title: `Review compensating controls for provider compromise blast radius`,
        description: `Consider CASB, DLP, conditional access, and network segmentation to limit impact of a provider-side breach.`,
      });
    }

    if (managed.length > 0) {
      recs.push({
        priority: 'low',
        title: `Document ${managed.length} managed/third-party asset(s) in asset inventory`,
        description: `Ensure managed assets are tracked separately with clear ownership boundaries and SLA expectations.`,
      });
    }

    return recs;
  }, [vendorRiskMetrics, vendorDependencies, providerName, managed]);

  if (infraLoading) {
    return (
      <div className="flex items-center justify-center p-12">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground mr-2" />
        <span className="text-muted-foreground">Analyzing vendor risk posture...</span>
      </div>
    );
  }

  // If no managed provider and no vendor dependencies, show empty state
  if (!providerName && vendorDependencies.length === 0 && vendorCves.length === 0) {
    return (
      <Card>
        <CardContent className="p-8 text-center text-muted-foreground">
          <ShieldCheck className="h-8 w-8 mx-auto mb-3 opacity-50" />
          <p>No managed provider or significant vendor dependencies detected.</p>
          <p className="text-xs mt-1">This scan did not identify third-party managed infrastructure requiring vendor risk assessment.</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <TooltipProvider>
      <div className="space-y-4">
        {/* ─── Vendor Risk Score Banner ─── */}
        <Card className={`border-l-4 ${
          vendorRiskMetrics.band === 'CRITICAL' ? 'border-l-red-500 bg-red-950/10' :
          vendorRiskMetrics.band === 'HIGH' ? 'border-l-orange-500 bg-orange-950/10' :
          vendorRiskMetrics.band === 'MEDIUM' ? 'border-l-yellow-500 bg-yellow-950/10' :
          vendorRiskMetrics.band === 'LOW' ? 'border-l-emerald-500 bg-emerald-950/10' :
          'border-l-slate-500 bg-slate-950/10'
        }`}>
          <CardContent className="p-4">
            <div className="flex flex-col md:flex-row md:items-center gap-4">
              <div className="flex items-center gap-3">
                <div className={`p-2.5 rounded-lg ${
                  vendorRiskMetrics.band === 'CRITICAL' ? 'bg-red-500/20' :
                  vendorRiskMetrics.band === 'HIGH' ? 'bg-orange-500/20' :
                  vendorRiskMetrics.band === 'MEDIUM' ? 'bg-yellow-500/20' :
                  'bg-emerald-500/20'
                }`}>
                  <ShieldAlert className={`h-6 w-6 ${
                    vendorRiskMetrics.band === 'CRITICAL' ? 'text-red-400' :
                    vendorRiskMetrics.band === 'HIGH' ? 'text-orange-400' :
                    vendorRiskMetrics.band === 'MEDIUM' ? 'text-yellow-400' :
                    'text-emerald-400'
                  }`} />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-lg font-bold">Vendor Risk: {vendorRiskMetrics.band}</span>
                    <Badge className={`text-xs ${SEVERITY_COLORS[vendorRiskMetrics.band.toLowerCase()] || SEVERITY_COLORS.minimal}`}>
                      {vendorRiskMetrics.score}/100
                    </Badge>
                    {/* Trend indicator */}
                    {riskHistory && riskHistory.history.length >= 2 && (
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <div className={`flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium ${
                            riskHistory.trend === 'improving' ? 'bg-emerald-500/20 text-emerald-400' :
                            riskHistory.trend === 'worsening' ? 'bg-red-500/20 text-red-400' :
                            'bg-slate-500/20 text-slate-400'
                          }`}>
                            {riskHistory.trend === 'improving' ? <TrendingDown className="h-3 w-3" /> :
                             riskHistory.trend === 'worsening' ? <TrendingUp className="h-3 w-3" /> :
                             <Minus className="h-3 w-3" />}
                            {riskHistory.delta !== 0 && (
                              <span>{riskHistory.delta > 0 ? '+' : ''}{riskHistory.delta}</span>
                            )}
                          </div>
                        </TooltipTrigger>
                        <TooltipContent>
                          <p className="text-xs">
                            {riskHistory.trend === 'improving' ? 'Vendor risk improving vs previous scan' :
                             riskHistory.trend === 'worsening' ? 'Vendor risk worsening vs previous scan' :
                             'Vendor risk stable vs previous scan'}
                            {riskHistory.delta !== 0 && ` (Δ ${riskHistory.delta > 0 ? '+' : ''}${riskHistory.delta} points)`}
                          </p>
                        </TooltipContent>
                      </Tooltip>
                    )}
                  </div>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    {providerName ? `Primary managed provider: ${providerName}` : 'Third-party vendor dependency assessment'}
                    {managed.length > 0 && ` · ${managed.length} managed asset(s) excluded from client risk score`}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-3 flex-1">
                <Progress
                  value={vendorRiskMetrics.score}
                  className="h-2 flex-1"
                />
                {riskHistory && riskHistory.history.length >= 2 && (
                  <VendorRiskSparkline history={riskHistory.history} />
                )}
              </div>
            </div>
          </CardContent>
        </Card>

        {/* ─── KPI Strip ─── */}
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
          <Card className="bg-card/50">
            <CardContent className="p-3 text-center">
              <div className="text-2xl font-bold text-slate-300">{vendorRiskMetrics.total}</div>
              <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Vendor CVEs</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50">
            <CardContent className="p-3 text-center">
              <div className="text-2xl font-bold text-red-400">{vendorRiskMetrics.critical}</div>
              <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Critical</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50">
            <CardContent className="p-3 text-center">
              <div className="text-2xl font-bold text-orange-400">{vendorRiskMetrics.high}</div>
              <div className="text-[10px] text-muted-foreground uppercase tracking-wider">High</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50">
            <CardContent className="p-3 text-center">
              <div className="text-2xl font-bold text-yellow-400">{vendorRiskMetrics.medium}</div>
              <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Medium</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50">
            <CardContent className="p-3 text-center">
              <div className="text-2xl font-bold text-blue-400">{vendorRiskMetrics.low}</div>
              <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Low</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50">
            <CardContent className="p-3 text-center">
              <div className="text-2xl font-bold text-amber-400">{vendorRiskMetrics.kev}</div>
              <div className="text-[10px] text-muted-foreground uppercase tracking-wider">KEV Listed</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50">
            <CardContent className="p-3 text-center">
              <div className="text-2xl font-bold text-purple-400">{managed.length}</div>
              <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Managed Assets</div>
            </CardContent>
          </Card>
        </div>

        {/* ─── Scan History Comparison ─── */}
        {riskHistory && riskHistory.history.length >= 2 && (
          <Collapsible open={expandedHistory} onOpenChange={setExpandedHistory}>
            <Card className="border-cyan-500/20">
              <CardHeader className="pb-3">
                <CollapsibleTrigger className="flex items-center justify-between w-full">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Activity className="h-4 w-4 text-cyan-400" />
                    Vendor Risk History ({riskHistory.history.length} scans)
                  </CardTitle>
                  {expandedHistory ? <ChevronUp className="h-4 w-4 text-muted-foreground" /> : <ChevronDown className="h-4 w-4 text-muted-foreground" />}
                </CollapsibleTrigger>
                <CardDescription>
                  Vendor risk score trend across previous scans of {domain}
                  {riskHistory.trend === 'improving' && ' — risk is decreasing'}
                  {riskHistory.trend === 'worsening' && ' — risk is increasing'}
                </CardDescription>
              </CardHeader>
              <CollapsibleContent>
                <CardContent className="pt-0">
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="border-b border-border/50">
                          <th className="text-left py-2 px-2 text-muted-foreground font-medium">Date</th>
                          <th className="text-center py-2 px-2 text-muted-foreground font-medium">Vendor Risk</th>
                          <th className="text-center py-2 px-2 text-muted-foreground font-medium">Band</th>
                          <th className="text-center py-2 px-2 text-muted-foreground font-medium">Vendor CVEs</th>
                          <th className="text-center py-2 px-2 text-muted-foreground font-medium">Overall Risk</th>
                          <th className="text-center py-2 px-2 text-muted-foreground font-medium">Assets</th>
                          <th className="text-center py-2 px-2 text-muted-foreground font-medium">Findings</th>
                          <th className="text-center py-2 px-2 text-muted-foreground font-medium">Δ</th>
                        </tr>
                      </thead>
                      <tbody>
                        {riskHistory.history.map((h, i) => {
                          const prev = i > 0 ? riskHistory.history[i - 1] : null;
                          const delta = prev ? h.vendorRiskScore - prev.vendorRiskScore : 0;
                          const isCurrent = h.scanId === scanId;
                          return (
                            <tr key={h.scanId} className={`border-b border-border/30 hover:bg-muted/30 ${isCurrent ? 'bg-cyan-500/5' : ''}`}>
                              <td className="py-2 px-2">
                                <div className="flex items-center gap-1.5">
                                  {isCurrent && <Badge className="text-[9px] bg-cyan-500/20 text-cyan-400 border-cyan-500/40">Current</Badge>}
                                  <span className="text-muted-foreground">
                                    {h.date ? new Date(h.date).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) : '—'}
                                  </span>
                                </div>
                              </td>
                              <td className="py-2 px-2 text-center font-mono font-bold">{h.vendorRiskScore}</td>
                              <td className="py-2 px-2 text-center">
                                <Badge className={`text-[10px] ${SEVERITY_COLORS[h.vendorRiskBand.toLowerCase()] || SEVERITY_COLORS.minimal}`}>
                                  {h.vendorRiskBand}
                                </Badge>
                              </td>
                              <td className="py-2 px-2 text-center">{h.vendorCveCount}</td>
                              <td className="py-2 px-2 text-center">
                                <Badge className={`text-[10px] ${SEVERITY_COLORS[h.overallRiskBand?.toString().toLowerCase()] || SEVERITY_COLORS.minimal}`}>
                                  {h.overallRiskScore}
                                </Badge>
                              </td>
                              <td className="py-2 px-2 text-center text-muted-foreground">{h.totalAssets}</td>
                              <td className="py-2 px-2 text-center text-muted-foreground">{h.totalFindings}</td>
                              <td className="py-2 px-2 text-center">
                                {i === 0 ? (
                                  <span className="text-muted-foreground">—</span>
                                ) : delta > 0 ? (
                                  <span className="text-red-400 font-medium">+{delta}</span>
                                ) : delta < 0 ? (
                                  <span className="text-emerald-400 font-medium">{delta}</span>
                                ) : (
                                  <span className="text-slate-400">0</span>
                                )}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </CardContent>
              </CollapsibleContent>
            </Card>
          </Collapsible>
        )}

        {/* ─── Shared Responsibility Model ─── */}
        {sharedResponsibility && (
          <Collapsible open={expandedSharedResp} onOpenChange={setExpandedSharedResp}>
            <Card className="border-indigo-500/20">
              <CardHeader className="pb-3">
                <CollapsibleTrigger className="flex items-center justify-between w-full">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Scale className="h-4 w-4 text-indigo-400" />
                    Shared Responsibility Model — {sharedResponsibility.provider}
                  </CardTitle>
                  {expandedSharedResp ? <ChevronUp className="h-4 w-4 text-muted-foreground" /> : <ChevronDown className="h-4 w-4 text-muted-foreground" />}
                </CollapsibleTrigger>
                <CardDescription>Security ownership boundaries between your organization and {sharedResponsibility.provider}</CardDescription>
              </CardHeader>
              <CollapsibleContent>
                <CardContent className="pt-0">
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    {/* Provider Scope */}
                    <div className="space-y-2">
                      <div className="flex items-center gap-2 mb-2">
                        <Building2 className="h-4 w-4 text-blue-400" />
                        <span className="text-xs font-semibold text-blue-400 uppercase tracking-wider">Provider Responsibility</span>
                      </div>
                      {sharedResponsibility.providerScope.map((item: string, i: number) => (
                        <div key={i} className="flex items-start gap-2 text-xs">
                          <CheckCircle2 className="h-3 w-3 text-blue-400 mt-0.5 shrink-0" />
                          <span className="text-muted-foreground">{item}</span>
                        </div>
                      ))}
                    </div>
                    {/* Customer Scope */}
                    <div className="space-y-2">
                      <div className="flex items-center gap-2 mb-2">
                        <Users className="h-4 w-4 text-amber-400" />
                        <span className="text-xs font-semibold text-amber-400 uppercase tracking-wider">Customer Responsibility</span>
                      </div>
                      {sharedResponsibility.customerScope.map((item: string, i: number) => (
                        <div key={i} className="flex items-start gap-2 text-xs">
                          <TriangleAlert className="h-3 w-3 text-amber-400 mt-0.5 shrink-0" />
                          <span className="text-muted-foreground">{item}</span>
                        </div>
                      ))}
                    </div>
                    {/* Shared Scope */}
                    <div className="space-y-2">
                      <div className="flex items-center gap-2 mb-2">
                        <Handshake className="h-4 w-4 text-emerald-400" />
                        <span className="text-xs font-semibold text-emerald-400 uppercase tracking-wider">Shared Responsibility</span>
                      </div>
                      {sharedResponsibility.sharedScope.map((item: string, i: number) => (
                        <div key={i} className="flex items-start gap-2 text-xs">
                          <Layers className="h-3 w-3 text-emerald-400 mt-0.5 shrink-0" />
                          <span className="text-muted-foreground">{item}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </CardContent>
              </CollapsibleContent>
            </Card>
          </Collapsible>
        )}

        {/* ─── Vendor Concentration Analysis ─── */}
        {vendorDependencies.length > 0 && (
          <Collapsible open={expandedConcentration} onOpenChange={setExpandedConcentration}>
            <Card>
              <CardHeader className="pb-3">
                <CollapsibleTrigger className="flex items-center justify-between w-full">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Network className="h-4 w-4 text-purple-400" />
                    Vendor Concentration ({vendorDependencies.length} vendors)
                  </CardTitle>
                  {expandedConcentration ? <ChevronUp className="h-4 w-4 text-muted-foreground" /> : <ChevronDown className="h-4 w-4 text-muted-foreground" />}
                </CollapsibleTrigger>
                <CardDescription>Third-party vendor dependencies and single-point-of-failure analysis</CardDescription>
              </CardHeader>
              <CollapsibleContent>
                <CardContent className="pt-0">
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="border-b border-border/50">
                          <th className="text-left py-2 px-2 text-muted-foreground font-medium">Vendor</th>
                          <th className="text-center py-2 px-2 text-muted-foreground font-medium">Services</th>
                          <th className="text-center py-2 px-2 text-muted-foreground font-medium">Criticality</th>
                          <th className="text-center py-2 px-2 text-muted-foreground font-medium">SPOF</th>
                          <th className="text-left py-2 px-2 text-muted-foreground font-medium">Provided Services</th>
                        </tr>
                      </thead>
                      <tbody>
                        {vendorDependencies.map((dep: any, i: number) => (
                          <tr key={i} className="border-b border-border/30 hover:bg-muted/30">
                            <td className="py-2 px-2 font-medium">{dep.vendor}</td>
                            <td className="py-2 px-2 text-center">{dep.serviceCount}</td>
                            <td className="py-2 px-2 text-center">
                              <Badge className={`text-[10px] ${SEVERITY_COLORS[dep.criticality] || ""}`}>{dep.criticality}</Badge>
                            </td>
                            <td className="py-2 px-2 text-center">
                              {dep.singlePointOfFailure ? (
                                <Tooltip>
                                  <TooltipTrigger>
                                    <XCircle className="h-3.5 w-3.5 text-red-400 mx-auto" />
                                  </TooltipTrigger>
                                  <TooltipContent><p className="text-xs">Single point of failure — vendor outage would cascade</p></TooltipContent>
                                </Tooltip>
                              ) : (
                                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 mx-auto" />
                              )}
                            </td>
                            <td className="py-2 px-2 text-muted-foreground">{dep.services.join(', ')}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </CardContent>
              </CollapsibleContent>
            </Card>
          </Collapsible>
        )}

        {/* ─── Supply Chain Risks ─── */}
        {supplyChainRisks.length > 0 && (
          <Card className="border-red-500/20">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-red-400" />
                Supply Chain Risks ({supplyChainRisks.length})
              </CardTitle>
              <CardDescription>Vendor concentration, missing defenses, and technology lifecycle risks</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3 pt-0">
              {supplyChainRisks.map((risk: any, i: number) => {
                const sevStyle = SEVERITY_COLORS[risk.severity] || SEVERITY_COLORS.medium;
                return (
                  <div key={i} className={`p-3 rounded-lg border ${sevStyle} space-y-2`}>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Badge className={`text-[10px] ${sevStyle}`}>{risk.severity}</Badge>
                        <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                          {risk.riskType.replace(/_/g, ' ')}
                        </span>
                      </div>
                    </div>
                    <p className="text-xs">{risk.description}</p>
                    <div className="text-xs text-muted-foreground">
                      <span className="font-medium">Recommendation:</span> {risk.recommendation}
                    </div>
                    {risk.affectedServices.length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-1">
                        {risk.affectedServices.map((svc: string, j: number) => (
                          <Badge key={j} variant="outline" className="text-[10px]">{svc}</Badge>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </CardContent>
          </Card>
        )}

        {/* ─── Vendor-Managed CVEs ─── */}
        {vendorCves.length > 0 && (
          <Collapsible open={expandedVendorCves} onOpenChange={setExpandedVendorCves}>
            <Card>
              <CardHeader className="pb-3">
                <CollapsibleTrigger className="flex items-center justify-between w-full">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Bug className="h-4 w-4 text-amber-400" />
                    Vendor-Managed CVEs ({vendorCves.length})
                  </CardTitle>
                  {expandedVendorCves ? <ChevronUp className="h-4 w-4 text-muted-foreground" /> : <ChevronDown className="h-4 w-4 text-muted-foreground" />}
                </CollapsibleTrigger>
                <CardDescription>
                  Vulnerabilities on managed provider infrastructure — provider's responsibility to patch, but represent supply chain risk
                </CardDescription>
              </CardHeader>
              <CollapsibleContent>
                <CardContent className="pt-0">
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="border-b border-border/50">
                          <th className="text-left py-2 px-2 text-muted-foreground font-medium">CVE ID</th>
                          <th className="text-center py-2 px-2 text-muted-foreground font-medium">CVSS</th>
                          <th className="text-center py-2 px-2 text-muted-foreground font-medium">Severity</th>
                          <th className="text-center py-2 px-2 text-muted-foreground font-medium">KEV</th>
                          <th className="text-left py-2 px-2 text-muted-foreground font-medium">Host</th>
                          <th className="text-left py-2 px-2 text-muted-foreground font-medium">Product</th>
                        </tr>
                      </thead>
                      <tbody>
                        {vendorCves.slice(0, 50).map((cve: any, i: number) => (
                          <tr key={i} className="border-b border-border/30 hover:bg-muted/30">
                            <td className="py-2 px-2">
                              <a
                                href={`https://nvd.nist.gov/vuln/detail/${cve.cveId}`}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-blue-400 hover:underline flex items-center gap-1"
                              >
                                {cve.cveId}
                                <ExternalLink className="h-2.5 w-2.5" />
                              </a>
                            </td>
                            <td className="py-2 px-2 text-center font-mono">
                              {cve.cvss ? cve.cvss.toFixed(1) : '—'}
                            </td>
                            <td className="py-2 px-2 text-center">
                              <Badge className={`text-[10px] ${SEVERITY_COLORS[cve.severity] || ""}`}>{cve.severity}</Badge>
                            </td>
                            <td className="py-2 px-2 text-center">
                              {cve.kevListed ? (
                                <Tooltip>
                                  <TooltipTrigger>
                                    <Badge className="text-[10px] bg-red-500/30 text-red-300 border-red-500/50">KEV</Badge>
                                  </TooltipTrigger>
                                  <TooltipContent><p className="text-xs">CISA Known Exploited Vulnerability — active exploitation confirmed</p></TooltipContent>
                                </Tooltip>
                              ) : (
                                <span className="text-muted-foreground">—</span>
                              )}
                            </td>
                            <td className="py-2 px-2 text-muted-foreground truncate max-w-[150px]">{cve.hostname || '—'}</td>
                            <td className="py-2 px-2 text-muted-foreground truncate max-w-[120px]">
                              {cve.product}{cve.version ? ` ${cve.version}` : ''}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {vendorCves.length > 50 && (
                      <p className="text-xs text-muted-foreground mt-2 text-center">
                        Showing 50 of {vendorCves.length} vendor-managed CVEs
                      </p>
                    )}
                  </div>
                </CardContent>
              </CollapsibleContent>
            </Card>
          </Collapsible>
        )}

        {/* ─── Managed Assets ─── */}
        {managed.length > 0 && (
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm flex items-center gap-2">
                <Cloud className="h-4 w-4 text-sky-400" />
                Managed/Third-Party Assets ({managed.length})
              </CardTitle>
              <CardDescription>
                Assets hosted on provider infrastructure — excluded from client risk score calculation
              </CardDescription>
            </CardHeader>
            <CardContent className="pt-0">
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-border/50">
                      <th className="text-left py-2 px-2 text-muted-foreground font-medium">Hostname</th>
                      <th className="text-left py-2 px-2 text-muted-foreground font-medium">Type</th>
                      <th className="text-left py-2 px-2 text-muted-foreground font-medium">Classification</th>
                    </tr>
                  </thead>
                  <tbody>
                    {managed.slice(0, 30).map((asset: any, i: number) => (
                      <tr key={i} className="border-b border-border/30 hover:bg-muted/30">
                        <td className="py-2 px-2 font-mono">{asset.hostname || '—'}</td>
                        <td className="py-2 px-2">
                          <Badge variant="outline" className="text-[10px]">{asset.assetType || 'unknown'}</Badge>
                        </td>
                        <td className="py-2 px-2 text-muted-foreground">
                          {asset.tags?.includes('reverse_whois') ? 'Reverse WHOIS — third-party registrant' :
                           asset.tags?.includes('related_domain') ? 'Related domain — different registrant' :
                           `Managed by ${providerName || 'provider'}`}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {managed.length > 30 && (
                  <p className="text-xs text-muted-foreground mt-2 text-center">
                    Showing 30 of {managed.length} managed assets
                  </p>
                )}
              </div>
            </CardContent>
          </Card>
        )}

        {/* ─── Recommendations ─── */}
        {recommendations.length > 0 && (
          <Collapsible open={expandedRecommendations} onOpenChange={setExpandedRecommendations}>
            <Card className="border-emerald-500/20">
              <CardHeader className="pb-3">
                <CollapsibleTrigger className="flex items-center justify-between w-full">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <FileText className="h-4 w-4 text-emerald-400" />
                    Vendor Risk Recommendations ({recommendations.length})
                  </CardTitle>
                  {expandedRecommendations ? <ChevronUp className="h-4 w-4 text-muted-foreground" /> : <ChevronDown className="h-4 w-4 text-muted-foreground" />}
                </CollapsibleTrigger>
                <CardDescription>Actionable steps to reduce vendor-related supply chain risk</CardDescription>
              </CardHeader>
              <CollapsibleContent>
                <CardContent className="space-y-3 pt-0">
                  {recommendations.map((rec, i) => (
                    <div key={i} className="flex items-start gap-3 p-3 rounded-lg bg-muted/30 border border-border/30">
                      <Badge className={`text-[10px] shrink-0 mt-0.5 ${SEVERITY_COLORS[rec.priority] || ""}`}>
                        {rec.priority}
                      </Badge>
                      <div>
                        <p className="text-xs font-medium">{rec.title}</p>
                        <p className="text-xs text-muted-foreground mt-1">{rec.description}</p>
                      </div>
                    </div>
                  ))}
                </CardContent>
              </CollapsibleContent>
            </Card>
          </Collapsible>
        )}

        {/* ─── Disclaimer ─── */}
        <Card className="bg-card/30">
          <CardContent className="p-3">
            <div className="flex items-start gap-2">
              <Info className="h-3.5 w-3.5 text-muted-foreground mt-0.5 shrink-0" />
              <p className="text-[10px] text-muted-foreground">
                Vendor risk assessment is based on passive reconnaissance data. CVEs attributed to managed providers
                are the provider's responsibility to remediate, but represent supply chain risk to your organization.
                This assessment should be used alongside vendor security questionnaires, SOC 2 reports, and contractual
                SLA reviews for a complete vendor risk picture.
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    </TooltipProvider>
  );
}
