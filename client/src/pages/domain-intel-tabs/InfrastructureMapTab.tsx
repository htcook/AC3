// @ts-nocheck
import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import {
  Server, Globe, Shield, AlertTriangle, ChevronDown, ChevronUp,
  Loader2, Database, Cpu, Network, Lock, Eye, Mail, Cloud, Layers,
  Activity, Info, ExternalLink, ShieldAlert, ShieldCheck, BarChart3,
  Fingerprint, Box, Wifi, Radio, Bug, Clock, RefreshCw, Plus, Trash2,
  TrendingUp, History, Rss, ToggleLeft, ToggleRight
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";

const CATEGORY_META: Record<string, { label: string; icon: any; color: string }> = {
  dns: { label: "DNS", icon: Globe, color: "text-blue-400" },
  email: { label: "Email", icon: Mail, color: "text-cyan-400" },
  cdn_waf: { label: "CDN / WAF", icon: Shield, color: "text-green-400" },
  web_server: { label: "Web Server", icon: Server, color: "text-slate-400" },
  application_framework: { label: "App Framework", icon: Box, color: "text-violet-400" },
  cms: { label: "CMS", icon: Layers, color: "text-pink-400" },
  database: { label: "Database", icon: Database, color: "text-amber-400" },
  authentication: { label: "Authentication", icon: Lock, color: "text-yellow-400" },
  cloud_hosting: { label: "Cloud Hosting", icon: Cloud, color: "text-sky-400" },
  cloud_storage: { label: "Cloud Storage", icon: Database, color: "text-orange-400" },
  container_orchestration: { label: "Containers", icon: Cpu, color: "text-teal-400" },
  ci_cd: { label: "CI/CD", icon: Activity, color: "text-indigo-400" },
  monitoring: { label: "Monitoring", icon: Activity, color: "text-emerald-400" },
  analytics: { label: "Analytics", icon: BarChart3, color: "text-purple-400" },
  payment: { label: "Payment", icon: Fingerprint, color: "text-rose-400" },
  communication: { label: "Communication", icon: Radio, color: "text-lime-400" },
  security_tools: { label: "Security Tools", icon: ShieldCheck, color: "text-green-400" },
  certificate_authority: { label: "Certificate Authority", icon: Lock, color: "text-emerald-400" },
  api_gateway: { label: "API Gateway", icon: Network, color: "text-blue-400" },
  load_balancer: { label: "Load Balancer", icon: Wifi, color: "text-cyan-400" },
  vpn: { label: "VPN", icon: Lock, color: "text-amber-400" },
  other: { label: "Other", icon: Server, color: "text-slate-400" },
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-red-400 bg-red-500/20 border-red-500/40",
  high: "text-orange-400 bg-orange-500/20 border-orange-500/40",
  medium: "text-yellow-400 bg-yellow-500/20 border-yellow-500/40",
  low: "text-blue-400 bg-blue-500/20 border-blue-500/40",
};

const MATURITY_COLORS: Record<string, { color: string; bg: string }> = {
  advanced: { color: "text-emerald-400", bg: "bg-emerald-500/20" },
  moderate: { color: "text-blue-400", bg: "bg-blue-500/20" },
  basic: { color: "text-yellow-400", bg: "bg-yellow-500/20" },
  minimal: { color: "text-red-400", bg: "bg-red-500/20" },
};

function ConfidenceBar({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  const color = pct >= 80 ? "bg-emerald-500" : pct >= 60 ? "bg-yellow-500" : "bg-red-500";
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-16 rounded-full bg-muted overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs text-muted-foreground">{pct}%</span>
    </div>
  );
}

export default function InfrastructureMapTab({ scanId, domain }: { scanId: number; domain?: string }) {
  const { data: infraMap, isLoading, error } = trpc.calderaProxy.inferInfrastructure.useQuery(
    { scanId },
    { staleTime: 5 * 60 * 1000 }
  );
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(new Set());
  const [expandedRisks, setExpandedRisks] = useState(false);
  const [expandedVendors, setExpandedVendors] = useState(false);
  const [expandedLifecycle, setExpandedLifecycle] = useState(false);
  const [expandedHistory, setExpandedHistory] = useState(false);
  const [expandedFeeds, setExpandedFeeds] = useState(false);

  // JARM History Timeline
  const { data: jarmTimeline, isLoading: timelineLoading } = trpc.calderaProxy.getJarmTimeline.useQuery(
    { domain: domain || '' },
    { enabled: !!domain, staleTime: 5 * 60 * 1000 }
  );

  // JARM Feed Sources
  const { data: feedSources, isLoading: feedsLoading, refetch: refetchFeeds } = trpc.calderaProxy.getJarmFeedSources.useQuery(
    undefined,
    { staleTime: 5 * 60 * 1000 }
  );
  const { data: feedStats } = trpc.calderaProxy.getJarmFeedStats.useQuery(
    undefined,
    { staleTime: 5 * 60 * 1000 }
  );

  const initFeedsMut = trpc.calderaProxy.initializeJarmFeeds.useMutation({
    onSuccess: (data) => {
      toast.success(`Initialized ${data.feedsAdded} default feed sources`);
      refetchFeeds();
    },
    onError: (err) => toast.error(`Failed to initialize feeds: ${err.message}`),
  });
  const refreshFeedMut = trpc.calderaProxy.refreshJarmFeed.useMutation({
    onSuccess: (data) => {
      if (data.success) {
        toast.success(`Refreshed: ${data.signaturesAdded} added, ${data.signaturesUpdated} updated`);
      } else {
        toast.error(`Feed refresh failed: ${data.error}`);
      }
      refetchFeeds();
    },
    onError: (err) => toast.error(`Refresh failed: ${err.message}`),
  });
  const refreshAllMut = trpc.calderaProxy.refreshAllJarmFeeds.useMutation({
    onSuccess: (results) => {
      const ok = results.filter((r: any) => r.success).length;
      toast.success(`Refreshed ${ok}/${results.length} feeds`);
      refetchFeeds();
    },
    onError: (err) => toast.error(`Refresh all failed: ${err.message}`),
  });
  const toggleFeedMut = trpc.calderaProxy.toggleJarmFeed.useMutation({
    onSuccess: () => { refetchFeeds(); },
    onError: (err) => toast.error(`Toggle failed: ${err.message}`),
  });
  const deleteFeedMut = trpc.calderaProxy.deleteJarmFeed.useMutation({
    onSuccess: () => { toast.success('Feed deleted'); refetchFeeds(); },
    onError: (err) => toast.error(`Delete failed: ${err.message}`),
  });

  const toggleCategory = (cat: string) => {
    setExpandedCategories(prev => {
      const next = new Set(prev);
      if (next.has(cat)) next.delete(cat);
      else next.add(cat);
      return next;
    });
  };

  // Group services by category
  const servicesByCategory = useMemo(() => {
    if (!infraMap) return new Map();
    const map = new Map<string, any[]>();
    for (const svc of infraMap.services) {
      if (!map.has(svc.category)) map.set(svc.category, []);
      map.get(svc.category)!.push(svc);
    }
    return map;
  }, [infraMap]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center p-12">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground mr-2" />
        <span className="text-muted-foreground">Inferring infrastructure from passive signals...</span>
      </div>
    );
  }

  if (error) {
    return (
      <Card className="border-red-500/30 bg-red-950/20">
        <CardContent className="p-6 text-center">
          <AlertTriangle className="h-6 w-6 text-red-400 mx-auto mb-2" />
          <p className="text-red-400">Failed to infer infrastructure: {error.message}</p>
        </CardContent>
      </Card>
    );
  }

  if (!infraMap || infraMap.services.length === 0) {
    return (
      <Card>
        <CardContent className="p-8 text-center text-muted-foreground">
          <Network className="h-8 w-8 mx-auto mb-3 opacity-50" />
          <p>No infrastructure signals detected from passive reconnaissance data.</p>
          <p className="text-xs mt-1">This may indicate limited DNS/header/technology fingerprinting data in the scan.</p>
        </CardContent>
      </Card>
    );
  }

  const summary = infraMap.summary;
  const maturityStyle = MATURITY_COLORS[summary.overallMaturity] || MATURITY_COLORS.minimal;

  return (
    <TooltipProvider>
      <div className="space-y-4">
        {/* ─── Summary Strip ─── */}
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
          <Card className="bg-card/50">
            <CardContent className="p-3 text-center">
              <div className="text-2xl font-bold text-blue-400">{summary.totalServices}</div>
              <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Services</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50">
            <CardContent className="p-3 text-center">
              <div className="text-2xl font-bold text-purple-400">{summary.totalVendors}</div>
              <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Vendors</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50">
            <CardContent className="p-3 text-center">
              <div className="text-2xl font-bold text-cyan-400">{summary.thirdPartyManaged}</div>
              <div className="text-[10px] text-muted-foreground uppercase tracking-wider">3rd-Party</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50">
            <CardContent className="p-3 text-center">
              <div className="text-2xl font-bold text-amber-400">{summary.externallyExposed}</div>
              <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Exposed</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50">
            <CardContent className="p-3 text-center">
              <div className={`text-2xl font-bold ${summary.criticalRisks > 0 ? "text-red-400" : "text-emerald-400"}`}>
                {summary.criticalRisks + summary.highRisks}
              </div>
              <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Risks</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50">
            <CardContent className="p-3 text-center">
              <div className={`text-lg font-bold capitalize ${maturityStyle.color}`}>{summary.overallMaturity}</div>
              <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Maturity</div>
            </CardContent>
          </Card>
        </div>

        {/* ─── Info Banner ─── */}
        <div className="flex items-start gap-2 p-3 rounded-lg bg-blue-950/30 border border-blue-500/20 text-xs text-blue-300">
          <Info className="h-3.5 w-3.5 mt-0.5 shrink-0" />
          <span>
            Infrastructure map inferred from passive reconnaissance signals including DNS, SPF, MX, HTTP headers, CNAME chains, Shodan, BuiltWith, certificate transparency, and JARM TLS fingerprinting. JARM fingerprints identify server TLS implementations to detect CDN, cloud hosting, and C2 frameworks.
          </span>
        </div>

        {/* ─── Service Categories ─── */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <Network className="h-4 w-4 text-blue-400" />
              Detected Services ({infraMap.services.length})
            </CardTitle>
            <CardDescription>Backend services, platforms, and vendor dependencies inferred from passive signals</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {Array.from(servicesByCategory.entries()).map(([category, services]) => {
              const meta = CATEGORY_META[category] || CATEGORY_META.other;
              const Icon = meta.icon;
              const isExpanded = expandedCategories.has(category);
              return (
                <Collapsible key={category} open={isExpanded} onOpenChange={() => toggleCategory(category)}>
                  <CollapsibleTrigger className="flex items-center justify-between w-full p-2.5 rounded-lg hover:bg-muted/50 transition-colors">
                    <div className="flex items-center gap-2">
                      <Icon className={`h-4 w-4 ${meta.color}`} />
                      <span className="text-sm font-medium">{meta.label}</span>
                      <Badge variant="outline" className="text-[10px] px-1.5 py-0">{services.length}</Badge>
                    </div>
                    <div className="flex items-center gap-2">
                      {services.some((s: any) => s.exposedExternally) && (
                        <Tooltip>
                          <TooltipTrigger>
                            <Eye className="h-3 w-3 text-amber-400" />
                          </TooltipTrigger>
                          <TooltipContent>Externally exposed</TooltipContent>
                        </Tooltip>
                      )}
                      {isExpanded ? <ChevronUp className="h-3.5 w-3.5 text-muted-foreground" /> : <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />}
                    </div>
                  </CollapsibleTrigger>
                  <CollapsibleContent>
                    <div className="ml-6 mt-1 space-y-2">
                      {services.map((svc: any) => (
                        <div key={svc.id} className="p-3 rounded-lg bg-muted/30 border border-border/50 space-y-2">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <span className="text-sm font-medium">{svc.name}</span>
                              {svc.provider && svc.provider !== svc.name && (
                                <Badge variant="outline" className="text-[10px] px-1.5 py-0 text-muted-foreground">{svc.provider}</Badge>
                              )}
                              {svc.version && (
                                <Badge variant="outline" className="text-[10px] px-1.5 py-0 text-blue-400 border-blue-500/30">v{svc.version}</Badge>
                              )}
                            </div>
                            <div className="flex items-center gap-2">
                              {svc.managedByThirdParty && (
                                <Tooltip>
                                  <TooltipTrigger>
                                    <Badge variant="outline" className="text-[10px] px-1.5 py-0 text-cyan-400 border-cyan-500/30">Managed</Badge>
                                  </TooltipTrigger>
                                  <TooltipContent>Third-party managed service</TooltipContent>
                                </Tooltip>
                              )}
                              {svc.exposedExternally && (
                                <Tooltip>
                                  <TooltipTrigger>
                                    <Badge variant="outline" className="text-[10px] px-1.5 py-0 text-amber-400 border-amber-500/30">External</Badge>
                                  </TooltipTrigger>
                                  <TooltipContent>Exposed to the internet</TooltipContent>
                                </Tooltip>
                              )}
                              <ConfidenceBar value={svc.confidence} />
                            </div>
                          </div>
                          {/* Evidence */}
                          {svc.evidence.length > 0 && (
                            <div className="text-xs text-muted-foreground space-y-0.5">
                              {svc.evidence.slice(0, 3).map((e: string, i: number) => (
                                <div key={i} className="flex items-start gap-1.5">
                                  <span className="text-muted-foreground/50 mt-0.5">-</span>
                                  <span className="break-all">{e}</span>
                                </div>
                              ))}
                              {svc.evidence.length > 3 && (
                                <span className="text-muted-foreground/50 text-[10px]">+{svc.evidence.length - 3} more evidence items</span>
                              )}
                            </div>
                          )}
                          {/* Ports */}
                          {svc.ports.length > 0 && (
                            <div className="flex items-center gap-1 flex-wrap">
                              <span className="text-[10px] text-muted-foreground">Ports:</span>
                              {svc.ports.map((p: number) => (
                                <Badge key={p} variant="outline" className="text-[10px] px-1 py-0 font-mono">{p}</Badge>
                              ))}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              );
            })}
          </CardContent>
        </Card>

        {/* ─── Supply Chain Risks ─── */}
        {infraMap.supplyChainRisks.length > 0 && (
          <Collapsible open={expandedRisks} onOpenChange={setExpandedRisks}>
            <Card className="border-red-500/20">
              <CardHeader className="pb-3">
                <CollapsibleTrigger className="flex items-center justify-between w-full">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <ShieldAlert className="h-4 w-4 text-red-400" />
                    Supply Chain Risks ({infraMap.supplyChainRisks.length})
                  </CardTitle>
                  {expandedRisks ? <ChevronUp className="h-4 w-4 text-muted-foreground" /> : <ChevronDown className="h-4 w-4 text-muted-foreground" />}
                </CollapsibleTrigger>
                <CardDescription>Vendor concentration, missing defenses, and technology lifecycle risks</CardDescription>
              </CardHeader>
              <CollapsibleContent>
                <CardContent className="space-y-3 pt-0">
                  {infraMap.supplyChainRisks.map((risk: any, i: number) => {
                    const sevStyle = SEVERITY_COLORS[risk.severity] || SEVERITY_COLORS.medium;
                    return (
                      <div key={i} className={`p-3 rounded-lg border ${sevStyle} space-y-2`}>
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <Badge className={`text-[10px] uppercase ${sevStyle}`}>{risk.severity}</Badge>
                            <span className="text-xs font-medium capitalize">{risk.riskType.replace(/_/g, " ")}</span>
                          </div>
                        </div>
                        <p className="text-xs text-muted-foreground">{risk.description}</p>
                        <div className="flex items-start gap-1.5 text-xs">
                          <ShieldCheck className="h-3 w-3 text-emerald-400 mt-0.5 shrink-0" />
                          <span className="text-emerald-400/80">{risk.recommendation}</span>
                        </div>
                        {risk.affectedServices.length > 0 && (
                          <div className="flex items-center gap-1 flex-wrap">
                            <span className="text-[10px] text-muted-foreground">Affected:</span>
                            {risk.affectedServices.slice(0, 5).map((s: string, j: number) => (
                              <Badge key={j} variant="outline" className="text-[10px] px-1 py-0">{s}</Badge>
                            ))}
                            {risk.affectedServices.length > 5 && (
                              <span className="text-[10px] text-muted-foreground">+{risk.affectedServices.length - 5} more</span>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </CardContent>
              </CollapsibleContent>
            </Card>
          </Collapsible>
        )}

        {/* ─── Vendor Dependencies ─── */}
        {infraMap.vendorDependencies.length > 0 && (
          <Collapsible open={expandedVendors} onOpenChange={setExpandedVendors}>
            <Card>
              <CardHeader className="pb-3">
                <CollapsibleTrigger className="flex items-center justify-between w-full">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Layers className="h-4 w-4 text-purple-400" />
                    Vendor Dependencies ({infraMap.vendorDependencies.length})
                  </CardTitle>
                  {expandedVendors ? <ChevronUp className="h-4 w-4 text-muted-foreground" /> : <ChevronDown className="h-4 w-4 text-muted-foreground" />}
                </CollapsibleTrigger>
                <CardDescription>Third-party vendor concentration and single-point-of-failure analysis</CardDescription>
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
                          <th className="text-left py-2 px-2 text-muted-foreground font-medium">Notes</th>
                        </tr>
                      </thead>
                      <tbody>
                        {infraMap.vendorDependencies.map((dep: any, i: number) => (
                          <tr key={i} className="border-b border-border/30 hover:bg-muted/30">
                            <td className="py-2 px-2 font-medium">{dep.vendor}</td>
                            <td className="py-2 px-2 text-center">{dep.serviceCount}</td>
                            <td className="py-2 px-2 text-center">
                              <Badge className={`text-[10px] ${SEVERITY_COLORS[dep.criticality] || ""}`}>{dep.criticality}</Badge>
                            </td>
                            <td className="py-2 px-2 text-center">
                              {dep.singlePointOfFailure ? (
                                <AlertTriangle className="h-3.5 w-3.5 text-red-400 mx-auto" />
                              ) : (
                                <span className="text-muted-foreground">-</span>
                              )}
                            </td>
                            <td className="py-2 px-2 text-muted-foreground">{dep.notes}</td>
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

        {/* ─── Technology Lifecycle ─── */}
        {infraMap.techLifecycle.length > 0 && (
          <Collapsible open={expandedLifecycle} onOpenChange={setExpandedLifecycle}>
            <Card>
              <CardHeader className="pb-3">
                <CollapsibleTrigger className="flex items-center justify-between w-full">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Activity className="h-4 w-4 text-emerald-400" />
                    Technology Lifecycle ({infraMap.techLifecycle.length})
                  </CardTitle>
                  {expandedLifecycle ? <ChevronUp className="h-4 w-4 text-muted-foreground" /> : <ChevronDown className="h-4 w-4 text-muted-foreground" />}
                </CollapsibleTrigger>
                <CardDescription>Version currency and end-of-life status for detected technologies</CardDescription>
              </CardHeader>
              <CollapsibleContent>
                <CardContent className="pt-0">
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="border-b border-border/50">
                          <th className="text-left py-2 px-2 text-muted-foreground font-medium">Technology</th>
                          <th className="text-left py-2 px-2 text-muted-foreground font-medium">Detected Version</th>
                          <th className="text-center py-2 px-2 text-muted-foreground font-medium">EOL Status</th>
                          <th className="text-left py-2 px-2 text-muted-foreground font-medium">Signal</th>
                          <th className="text-left py-2 px-2 text-muted-foreground font-medium">Risk Note</th>
                        </tr>
                      </thead>
                      <tbody>
                        {infraMap.techLifecycle.map((tech: any, i: number) => {
                          const eolColors: Record<string, string> = {
                            current: "text-emerald-400 bg-emerald-500/20",
                            approaching_eol: "text-yellow-400 bg-yellow-500/20",
                            eol: "text-red-400 bg-red-500/20",
                            unknown: "text-slate-400 bg-slate-500/20",
                          };
                          return (
                            <tr key={i} className="border-b border-border/30 hover:bg-muted/30">
                              <td className="py-2 px-2 font-medium">{tech.technology}</td>
                              <td className="py-2 px-2 font-mono">{tech.detectedVersion || "-"}</td>
                              <td className="py-2 px-2 text-center">
                                <Badge className={`text-[10px] ${eolColors[tech.eolStatus] || eolColors.unknown}`}>
                                  {tech.eolStatus.replace(/_/g, " ").toUpperCase()}
                                </Badge>
                              </td>
                              <td className="py-2 px-2 text-muted-foreground">{tech.patchCadenceSignal}</td>
                              <td className="py-2 px-2 text-muted-foreground">{tech.riskNote}</td>
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

        {/* ─── JARM TLS Fingerprint Analysis ─── */}
        {infraMap.jarmAnalysis && infraMap.jarmAnalysis.fingerprintsCollected > 0 && (
          <Card className={infraMap.jarmAnalysis.c2Detected ? "border-red-500/50 bg-red-950/10" : "bg-card/50"}>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm flex items-center gap-2">
                <Fingerprint className={`h-4 w-4 ${infraMap.jarmAnalysis.c2Detected ? "text-red-400" : "text-emerald-400"}`} />
                JARM TLS Fingerprint Analysis
                {infraMap.jarmAnalysis.c2Detected && (
                  <Badge className="bg-red-500/20 text-red-400 border-red-500/40 text-[10px] ml-1">
                    <Bug className="h-2.5 w-2.5 mr-0.5" /> C2 DETECTED
                  </Badge>
                )}
              </CardTitle>
              <CardDescription>
                {infraMap.jarmAnalysis.fingerprintsCollected} TLS fingerprint(s) collected,{" "}
                {infraMap.jarmAnalysis.matchesFound} matched to known infrastructure
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {/* Status badges */}
              <div className="flex flex-wrap gap-2">
                {infraMap.jarmAnalysis.cdnCorroborated && (
                  <Badge variant="outline" className="text-[10px] text-green-400 border-green-500/40 bg-green-500/10">
                    <ShieldCheck className="h-2.5 w-2.5 mr-1" /> CDN Corroborated
                  </Badge>
                )}
                {infraMap.jarmAnalysis.cloudCorroborated && (
                  <Badge variant="outline" className="text-[10px] text-sky-400 border-sky-500/40 bg-sky-500/10">
                    <Cloud className="h-2.5 w-2.5 mr-1" /> Cloud Hosting Corroborated
                  </Badge>
                )}
                {infraMap.jarmAnalysis.serverIdentified && (
                  <Badge variant="outline" className="text-[10px] text-slate-400 border-slate-500/40 bg-slate-500/10">
                    <Server className="h-2.5 w-2.5 mr-1" /> Server Software Identified
                  </Badge>
                )}
              </div>

              {/* Matches table */}
              {infraMap.jarmAnalysis.matches.length > 0 && (
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-border/50">
                        <th className="text-left py-1.5 px-2 text-muted-foreground font-medium">Hash (prefix)</th>
                        <th className="text-left py-1.5 px-2 text-muted-foreground font-medium">Matched Provider</th>
                        <th className="text-left py-1.5 px-2 text-muted-foreground font-medium">Type</th>
                        <th className="text-left py-1.5 px-2 text-muted-foreground font-medium">Source</th>
                        <th className="text-left py-1.5 px-2 text-muted-foreground font-medium">Confidence</th>
                      </tr>
                    </thead>
                    <tbody>
                      {infraMap.jarmAnalysis.matches.map((match: any, i: number) => (
                        <tr key={i} className={`border-b border-border/30 ${match.matchType === "c2" ? "bg-red-950/20" : ""}`}>
                          <td className="py-1.5 px-2 font-mono text-[10px] text-muted-foreground">
                            {match.hash.substring(0, 20)}…
                          </td>
                          <td className="py-1.5 px-2">
                            {match.matchedProvider ? (
                              <span className={match.matchType === "c2" ? "text-red-400 font-medium" : ""}>
                                {match.matchedProvider}
                              </span>
                            ) : (
                              <span className="text-muted-foreground italic">Unknown</span>
                            )}
                          </td>
                          <td className="py-1.5 px-2">
                            <Badge variant="outline" className={`text-[9px] px-1 py-0 ${
                              match.matchType === "c2" ? "text-red-400 border-red-500/40" :
                              match.matchType === "cdn" ? "text-green-400 border-green-500/40" :
                              match.matchType === "cloud" ? "text-sky-400 border-sky-500/40" :
                              match.matchType === "server" ? "text-slate-400 border-slate-500/40" :
                              "text-muted-foreground border-border"
                            }`}>
                              {match.matchType.toUpperCase()}
                            </Badge>
                          </td>
                          <td className="py-1.5 px-2 text-muted-foreground">{match.source}</td>
                          <td className="py-1.5 px-2"><ConfidenceBar value={match.confidence} /></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {/* JARM notes */}
              {infraMap.jarmAnalysis.notes.length > 0 && (
                <div className="space-y-1 pt-1">
                  {infraMap.jarmAnalysis.notes.map((note: string, i: number) => (
                    <div key={i} className={`text-xs flex items-start gap-1.5 ${
                      note.includes("CRITICAL") ? "text-red-400" :
                      note.includes("corroborates") ? "text-emerald-400" :
                      "text-muted-foreground"
                    }`}>
                      <span className="mt-0.5">•</span>
                      <span>{note}</span>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {/* ─── JARM History Timeline ─── */}
        {domain && (
          <Card className="bg-card/50">
            <Collapsible open={expandedHistory} onOpenChange={setExpandedHistory}>
              <CollapsibleTrigger className="w-full">
                <CardHeader className="pb-2 cursor-pointer hover:bg-muted/20 transition-colors">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <History className="h-4 w-4 text-cyan-400" />
                    JARM History Timeline
                    <Badge variant="outline" className="text-[10px] ml-auto mr-2">
                      {timelineLoading ? '...' : `${jarmTimeline?.totalRecords || 0} records`}
                    </Badge>
                    {jarmTimeline?.criticalAlerts ? (
                      <Badge variant="outline" className="text-[10px] text-red-400 border-red-500/40 bg-red-500/10">
                        {jarmTimeline.criticalAlerts} critical
                      </Badge>
                    ) : null}
                    {expandedHistory ? <ChevronUp className="h-4 w-4 text-muted-foreground" /> : <ChevronDown className="h-4 w-4 text-muted-foreground" />}
                  </CardTitle>
                  <CardDescription className="text-xs">Track TLS fingerprint changes across scans to detect infrastructure modifications</CardDescription>
                </CardHeader>
              </CollapsibleTrigger>
              <CollapsibleContent>
                <CardContent className="pt-0 space-y-3">
                  {timelineLoading ? (
                    <div className="flex items-center gap-2 text-xs text-muted-foreground py-4">
                      <Loader2 className="h-3 w-3 animate-spin" /> Loading timeline...
                    </div>
                  ) : !jarmTimeline || jarmTimeline.totalRecords === 0 ? (
                    <div className="text-xs text-muted-foreground py-4 text-center">
                      No JARM history recorded yet. History will populate after subsequent scans of this domain.
                    </div>
                  ) : (
                    <>
                      {/* Summary stats */}
                      <div className="grid grid-cols-4 gap-2">
                        <div className="bg-muted/30 rounded-lg p-2 text-center">
                          <div className="text-lg font-bold">{jarmTimeline.totalRecords}</div>
                          <div className="text-[10px] text-muted-foreground">Total Records</div>
                        </div>
                        <div className="bg-muted/30 rounded-lg p-2 text-center">
                          <div className="text-lg font-bold">{jarmTimeline.uniqueHosts}</div>
                          <div className="text-[10px] text-muted-foreground">Unique Hosts</div>
                        </div>
                        <div className="bg-muted/30 rounded-lg p-2 text-center">
                          <div className={`text-lg font-bold ${jarmTimeline.changesDetected > 0 ? 'text-amber-400' : ''}`}>{jarmTimeline.changesDetected}</div>
                          <div className="text-[10px] text-muted-foreground">Changes Detected</div>
                        </div>
                        <div className="bg-muted/30 rounded-lg p-2 text-center">
                          <div className={`text-lg font-bold ${jarmTimeline.criticalAlerts > 0 ? 'text-red-400' : ''}`}>{jarmTimeline.criticalAlerts}</div>
                          <div className="text-[10px] text-muted-foreground">Critical Alerts</div>
                        </div>
                      </div>

                      {/* Change alerts */}
                      {jarmTimeline.alerts.length > 0 && (
                        <div className="space-y-2">
                          <div className="text-xs font-medium text-muted-foreground flex items-center gap-1.5">
                            <AlertTriangle className="h-3 w-3" /> Change Alerts
                          </div>
                          {jarmTimeline.alerts.slice(0, 10).map((alert: any, i: number) => (
                            <div key={i} className={`rounded-lg border p-2 text-xs ${
                              alert.severity === 'critical' ? 'border-red-500/40 bg-red-950/20' :
                              alert.severity === 'high' ? 'border-orange-500/40 bg-orange-950/20' :
                              alert.severity === 'medium' ? 'border-yellow-500/40 bg-yellow-950/20' :
                              'border-border/50 bg-muted/20'
                            }`}>
                              <div className="flex items-center gap-2 mb-1">
                                <Badge variant="outline" className={`text-[9px] px-1 py-0 ${
                                  alert.severity === 'critical' ? 'text-red-400 border-red-500/40' :
                                  alert.severity === 'high' ? 'text-orange-400 border-orange-500/40' :
                                  alert.severity === 'medium' ? 'text-yellow-400 border-yellow-500/40' :
                                  'text-muted-foreground border-border'
                                }`}>
                                  {alert.severity.toUpperCase()}
                                </Badge>
                                <span className="font-mono text-muted-foreground">{alert.host}:{alert.port}</span>
                                <span className="text-muted-foreground ml-auto">{new Date(alert.scannedAt).toLocaleDateString()}</span>
                              </div>
                              <div className="text-muted-foreground">{alert.description}</div>
                            </div>
                          ))}
                        </div>
                      )}

                      {/* Recent records table */}
                      <div className="overflow-x-auto">
                        <table className="w-full text-xs">
                          <thead>
                            <tr className="border-b border-border/50">
                              <th className="text-left py-1.5 px-2 text-muted-foreground font-medium">Scan</th>
                              <th className="text-left py-1.5 px-2 text-muted-foreground font-medium">Hash (prefix)</th>
                              <th className="text-left py-1.5 px-2 text-muted-foreground font-medium">Provider</th>
                              <th className="text-left py-1.5 px-2 text-muted-foreground font-medium">Source</th>
                              <th className="text-left py-1.5 px-2 text-muted-foreground font-medium">Change</th>
                              <th className="text-left py-1.5 px-2 text-muted-foreground font-medium">Date</th>
                            </tr>
                          </thead>
                          <tbody>
                            {jarmTimeline.records.slice(0, 20).map((rec: any, i: number) => (
                              <tr key={i} className={`border-b border-border/30 ${rec.changeDetected ? 'bg-amber-950/10' : ''}`}>
                                <td className="py-1.5 px-2 text-muted-foreground">#{rec.scanId}</td>
                                <td className="py-1.5 px-2 font-mono text-[10px] text-muted-foreground">{rec.jarmHash.substring(0, 16)}…</td>
                                <td className="py-1.5 px-2">{rec.matchedProvider || <span className="text-muted-foreground italic">Unknown</span>}</td>
                                <td className="py-1.5 px-2 text-muted-foreground">{rec.source}</td>
                                <td className="py-1.5 px-2">
                                  {rec.changeDetected ? (
                                    <Badge variant="outline" className={`text-[9px] px-1 py-0 ${
                                      rec.changeSeverity === 'critical' ? 'text-red-400 border-red-500/40' :
                                      rec.changeSeverity === 'high' ? 'text-orange-400 border-orange-500/40' :
                                      rec.changeSeverity === 'medium' ? 'text-yellow-400 border-yellow-500/40' :
                                      'text-muted-foreground border-border'
                                    }`}>
                                      {(rec.changeType || 'changed').replace(/_/g, ' ')}
                                    </Badge>
                                  ) : (
                                    <span className="text-muted-foreground/50">—</span>
                                  )}
                                </td>
                                <td className="py-1.5 px-2 text-muted-foreground">{new Date(rec.scannedAt).toLocaleDateString()}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </>
                  )}
                </CardContent>
              </CollapsibleContent>
            </Collapsible>
          </Card>
        )}

        {/* ─── Community Signature Feeds ─── */}
        <Card className="bg-card/50">
          <Collapsible open={expandedFeeds} onOpenChange={setExpandedFeeds}>
            <CollapsibleTrigger className="w-full">
              <CardHeader className="pb-2 cursor-pointer hover:bg-muted/20 transition-colors">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Rss className="h-4 w-4 text-purple-400" />
                  Community JARM Signature Feeds
                  <Badge variant="outline" className="text-[10px] ml-auto mr-2">
                    {feedsLoading ? '...' : `${feedStats?.totalSignatures || 0} signatures`}
                  </Badge>
                  {feedStats?.c2Signatures ? (
                    <Badge variant="outline" className="text-[10px] text-red-400 border-red-500/40 bg-red-500/10">
                      {feedStats.c2Signatures} C2
                    </Badge>
                  ) : null}
                  {expandedFeeds ? <ChevronUp className="h-4 w-4 text-muted-foreground" /> : <ChevronDown className="h-4 w-4 text-muted-foreground" />}
                </CardTitle>
                <CardDescription className="text-xs">Auto-update JARM signatures from public threat intelligence feeds</CardDescription>
              </CardHeader>
            </CollapsibleTrigger>
            <CollapsibleContent>
              <CardContent className="pt-0 space-y-3">
                {/* Feed stats summary */}
                {feedStats && (
                  <div className="grid grid-cols-4 gap-2">
                    <div className="bg-muted/30 rounded-lg p-2 text-center">
                      <div className="text-lg font-bold">{feedStats.totalFeeds}</div>
                      <div className="text-[10px] text-muted-foreground">Total Feeds</div>
                    </div>
                    <div className="bg-muted/30 rounded-lg p-2 text-center">
                      <div className="text-lg font-bold text-green-400">{feedStats.enabledFeeds}</div>
                      <div className="text-[10px] text-muted-foreground">Enabled</div>
                    </div>
                    <div className="bg-muted/30 rounded-lg p-2 text-center">
                      <div className="text-lg font-bold">{feedStats.totalSignatures}</div>
                      <div className="text-[10px] text-muted-foreground">Signatures</div>
                    </div>
                    <div className="bg-muted/30 rounded-lg p-2 text-center">
                      <div className={`text-lg font-bold ${feedStats.c2Signatures > 0 ? 'text-red-400' : ''}`}>{feedStats.c2Signatures}</div>
                      <div className="text-[10px] text-muted-foreground">C2 Signatures</div>
                    </div>
                  </div>
                )}

                {/* Action buttons */}
                <div className="flex gap-2">
                  <Button
                    size="sm"
                    variant="outline"
                    className="text-xs h-7"
                    onClick={() => initFeedsMut.mutate()}
                    disabled={initFeedsMut.isPending}
                  >
                    {initFeedsMut.isPending ? <Loader2 className="h-3 w-3 animate-spin mr-1" /> : <Plus className="h-3 w-3 mr-1" />}
                    Initialize Defaults
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    className="text-xs h-7"
                    onClick={() => refreshAllMut.mutate()}
                    disabled={refreshAllMut.isPending}
                  >
                    {refreshAllMut.isPending ? <Loader2 className="h-3 w-3 animate-spin mr-1" /> : <RefreshCw className="h-3 w-3 mr-1" />}
                    Refresh All
                  </Button>
                </div>

                {/* Feed sources list */}
                {feedsLoading ? (
                  <div className="flex items-center gap-2 text-xs text-muted-foreground py-4">
                    <Loader2 className="h-3 w-3 animate-spin" /> Loading feeds...
                  </div>
                ) : !feedSources || feedSources.length === 0 ? (
                  <div className="text-xs text-muted-foreground py-4 text-center">
                    No feed sources configured. Click "Initialize Defaults" to add community feeds.
                  </div>
                ) : (
                  <div className="space-y-2">
                    {feedSources.map((feed: any) => (
                      <div key={feed.feedId} className={`rounded-lg border p-3 text-xs ${
                        feed.enabled ? 'border-border/50 bg-muted/10' : 'border-border/30 bg-muted/5 opacity-60'
                      }`}>
                        <div className="flex items-center gap-2 mb-1">
                          <Rss className={`h-3 w-3 ${feed.enabled ? 'text-purple-400' : 'text-muted-foreground'}`} />
                          <span className="font-medium">{feed.name}</span>
                          <Badge variant="outline" className="text-[9px] px-1 py-0">{feed.feedType}</Badge>
                          {feed.lastRefreshStatus === 'success' && (
                            <Badge variant="outline" className="text-[9px] px-1 py-0 text-green-400 border-green-500/40">
                              OK
                            </Badge>
                          )}
                          {feed.lastRefreshStatus === 'error' && (
                            <Badge variant="outline" className="text-[9px] px-1 py-0 text-red-400 border-red-500/40">
                              Error
                            </Badge>
                          )}
                          <div className="ml-auto flex items-center gap-1">
                            <Button
                              size="sm"
                              variant="ghost"
                              className="h-5 w-5 p-0"
                              onClick={(e) => { e.stopPropagation(); refreshFeedMut.mutate({ feedId: feed.feedId }); }}
                              disabled={refreshFeedMut.isPending}
                              title="Refresh this feed"
                            >
                              <RefreshCw className={`h-3 w-3 ${refreshFeedMut.isPending ? 'animate-spin' : ''}`} />
                            </Button>
                            <Button
                              size="sm"
                              variant="ghost"
                              className="h-5 w-5 p-0"
                              onClick={(e) => { e.stopPropagation(); toggleFeedMut.mutate({ feedId: feed.feedId, enabled: !feed.enabled }); }}
                              title={feed.enabled ? 'Disable feed' : 'Enable feed'}
                            >
                              {feed.enabled ? <ToggleRight className="h-3 w-3 text-green-400" /> : <ToggleLeft className="h-3 w-3 text-muted-foreground" />}
                            </Button>
                            <Button
                              size="sm"
                              variant="ghost"
                              className="h-5 w-5 p-0 text-red-400 hover:text-red-300"
                              onClick={(e) => { e.stopPropagation(); if (confirm(`Delete feed "${feed.name}" and all its signatures?`)) deleteFeedMut.mutate({ feedId: feed.feedId }); }}
                              title="Delete feed"
                            >
                              <Trash2 className="h-3 w-3" />
                            </Button>
                          </div>
                        </div>
                        {feed.description && <div className="text-muted-foreground mb-1">{feed.description}</div>}
                        <div className="flex items-center gap-3 text-muted-foreground/70">
                          <span>{feed.totalSignatures} sigs</span>
                          <span>Every {feed.refreshIntervalHours}h</span>
                          {feed.lastRefreshAt && <span>Last: {new Date(feed.lastRefreshAt).toLocaleString()}</span>}
                          {feed.lastRefreshError && <span className="text-red-400 truncate max-w-[200px]" title={feed.lastRefreshError}>{feed.lastRefreshError}</span>}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </CollapsibleContent>
          </Collapsible>
        </Card>

        {/* ─── Inference Notes ─── */}
        {infraMap.inferenceNotes.length > 0 && (
          <Card className="bg-card/50">
            <CardHeader className="pb-2">
              <CardTitle className="text-xs flex items-center gap-2 text-muted-foreground">
                <Info className="h-3 w-3" />
                Inference Notes
              </CardTitle>
            </CardHeader>
            <CardContent className="pt-0">
              <div className="space-y-1">
                {infraMap.inferenceNotes.map((note: string, i: number) => (
                  <div key={i} className="text-xs text-muted-foreground flex items-start gap-1.5">
                    <span className="text-muted-foreground/50 mt-0.5">-</span>
                    <span className={note.startsWith("WARNING") || note.startsWith("CRITICAL") ? (note.startsWith("CRITICAL") ? "text-red-400 font-medium" : "text-amber-400") : ""}>{note}</span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </TooltipProvider>
  );
}
