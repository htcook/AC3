// @ts-nocheck
import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Shield, AlertTriangle, Globe, Network, Loader2, Info, CheckCircle2, XCircle,
  RefreshCw, Lock, ShieldCheck, ShieldX, ExternalLink, ChevronDown, ChevronUp,
  Mail, Link2, Clock, Fingerprint, Zap, Eye
} from "lucide-react";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/10 text-red-400 border-red-500/30",
  high: "bg-orange-500/10 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/10 text-blue-400 border-blue-500/30",
  info: "bg-zinc-500/10 text-zinc-400 border-zinc-500/30",
};

const RISK_COLORS: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-emerald-400",
};

const CATEGORY_ICONS: Record<string, string> = {
  dangling_dns: "🔗",
  dnssec: "🔐",
  zone_transfer: "📋",
  cache_poisoning: "💉",
  open_resolver: "🌐",
  amplification: "📡",
  wildcard: "✳️",
  email_security: "📧",
  caa: "📜",
  zone_walking: "🚶",
  tunneling_indicator: "🕳️",
  version_disclosure: "🏷️",
  dns_cookie: "🍪",
  rate_limiting: "⏱️",
  rebinding: "🔄",
};

export default function DnsSecurityTab({ domain, pipeline }: { domain: string; pipeline: any }) {
  const [activeSubTab, setActiveSubTab] = useState("overview");
  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set());

  // Get DNS security report from pipeline (if already run during DI scan)
  const pipelineReport = pipeline?.passiveDiscovery?.dnsSecurityReport;

  // On-demand assessment mutation
  const assessMut = trpc.dnsSecurity.runAssessment.useMutation({
    onSuccess: () => toast.success("DNS security assessment complete"),
    onError: (err: any) => toast.error(`Assessment failed: ${err.message}`),
  });

  // Use pipeline data or on-demand result
  const report = assessMut.data || pipelineReport;

  // Get check categories for display
  const { data: categories } = trpc.dnsSecurity.getCheckCategories.useQuery();
  const { data: mitreMapping } = trpc.dnsSecurity.getMitreMapping.useQuery();

  const toggleFinding = (id: string) => {
    setExpandedFindings(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const runAssessment = () => {
    assessMut.mutate({ domain, context: "di_scan" });
  };

  // Group findings by category
  const findingsByCategory = report?.findings?.reduce((acc: Record<string, any[]>, f: any) => {
    if (!acc[f.category]) acc[f.category] = [];
    acc[f.category].push(f);
    return acc;
  }, {} as Record<string, any[]>) || {};

  const severityCounts = report?.summary || { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold text-zinc-100 flex items-center gap-2">
            <Shield className="h-5 w-5 text-cyan-400" />
            DNS Security Assessment
          </h3>
          <p className="text-sm text-zinc-400 mt-1">
            Comprehensive DNS security validation — 15 parallel checks, 35+ takeover fingerprints, full DNSSEC chain-of-trust
          </p>
        </div>
        <Button
          onClick={runAssessment}
          disabled={assessMut.isPending}
          variant="outline"
          size="sm"
          className="border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/10"
        >
          {assessMut.isPending ? (
            <><Loader2 className="h-4 w-4 animate-spin mr-2" /> Scanning...</>
          ) : (
            <><RefreshCw className="h-4 w-4 mr-2" /> Run Assessment</>
          )}
        </Button>
      </div>

      {!report ? (
        <Card className="border-zinc-700/50 bg-zinc-900/50">
          <CardContent className="py-12 text-center">
            <Shield className="h-12 w-12 text-zinc-600 mx-auto mb-4" />
            <p className="text-zinc-400 mb-2">No DNS security assessment data available</p>
            <p className="text-sm text-zinc-500 mb-4">
              {pipelineReport === null
                ? "The DNS security validator encountered an error during the scan. Click below to retry."
                : "Click \"Run Assessment\" to perform a comprehensive DNS security scan."}
            </p>
            <Button onClick={runAssessment} disabled={assessMut.isPending} size="sm">
              {assessMut.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Zap className="h-4 w-4 mr-2" />}
              Run DNS Security Assessment
            </Button>
          </CardContent>
        </Card>
      ) : (
        <>
          {/* Sub-tabs */}
          <Tabs value={activeSubTab} onValueChange={setActiveSubTab}>
            <TabsList className="bg-zinc-800/50 border border-zinc-700/50">
              <TabsTrigger value="overview">Overview</TabsTrigger>
              <TabsTrigger value="findings">
                Findings
                {report.summary.totalFindings > 0 && (
                  <Badge variant="secondary" className="ml-1.5 text-xs">{report.summary.totalFindings}</Badge>
                )}
              </TabsTrigger>
              <TabsTrigger value="records">DNS Records</TabsTrigger>
              <TabsTrigger value="dnssec">DNSSEC</TabsTrigger>
              <TabsTrigger value="mitre">MITRE ATT&CK</TabsTrigger>
            </TabsList>

            {/* ─── Overview Sub-Tab ─── */}
            <TabsContent value="overview" className="space-y-4 mt-4">
              {/* Risk Summary Cards */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <Card className="border-zinc-700/50 bg-zinc-900/50">
                  <CardContent className="pt-4 pb-4">
                    <div className="text-sm text-zinc-400 mb-1">Overall Risk</div>
                    <div className={`text-2xl font-bold uppercase ${RISK_COLORS[report.summary.overallRisk] || "text-zinc-300"}`}>
                      {report.summary.overallRisk}
                    </div>
                  </CardContent>
                </Card>
                <Card className="border-zinc-700/50 bg-zinc-900/50">
                  <CardContent className="pt-4 pb-4">
                    <div className="text-sm text-zinc-400 mb-1">Total Findings</div>
                    <div className="text-2xl font-bold text-zinc-100">{report.summary.totalFindings}</div>
                    <div className="flex gap-1.5 mt-1">
                      {severityCounts.critical > 0 && <Badge className="bg-red-500/20 text-red-400 text-xs">{severityCounts.critical} Crit</Badge>}
                      {severityCounts.high > 0 && <Badge className="bg-orange-500/20 text-orange-400 text-xs">{severityCounts.high} High</Badge>}
                      {severityCounts.medium > 0 && <Badge className="bg-yellow-500/20 text-yellow-400 text-xs">{severityCounts.medium} Med</Badge>}
                    </div>
                  </CardContent>
                </Card>
                <Card className="border-zinc-700/50 bg-zinc-900/50">
                  <CardContent className="pt-4 pb-4">
                    <div className="text-sm text-zinc-400 mb-1">Checks Passed</div>
                    <div className="text-2xl font-bold text-emerald-400">
                      {report.summary.passedChecks}/{report.summary.totalChecks}
                    </div>
                    <Progress
                      value={(report.summary.passedChecks / report.summary.totalChecks) * 100}
                      className="mt-2 h-1.5"
                    />
                  </CardContent>
                </Card>
                <Card className="border-zinc-700/50 bg-zinc-900/50">
                  <CardContent className="pt-4 pb-4">
                    <div className="text-sm text-zinc-400 mb-1">DNSSEC</div>
                    <div className="flex items-center gap-2">
                      {report.dnssec.enabled ? (
                        <><ShieldCheck className="h-5 w-5 text-emerald-400" /><span className="text-emerald-400 font-medium">Enabled</span></>
                      ) : (
                        <><ShieldX className="h-5 w-5 text-red-400" /><span className="text-red-400 font-medium">Not Enabled</span></>
                      )}
                    </div>
                    {report.dnssec.enabled && (
                      <div className="text-xs text-zinc-500 mt-1">
                        Algorithm: <span className="text-zinc-300">{report.dnssec.algorithmStrength}</span>
                      </div>
                    )}
                  </CardContent>
                </Card>
              </div>

              {/* Check Categories Grid */}
              <Card className="border-zinc-700/50 bg-zinc-900/50">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-medium text-zinc-300">Security Check Results</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                    {(categories || []).map((cat: any) => {
                      const catFindings = findingsByCategory[cat.id] || [];
                      const hasCritical = catFindings.some((f: any) => f.severity === "critical");
                      const hasHigh = catFindings.some((f: any) => f.severity === "high");
                      const passed = catFindings.length === 0;
                      return (
                        <div
                          key={cat.id}
                          className={`flex items-center gap-3 p-3 rounded-lg border ${
                            hasCritical ? "border-red-500/30 bg-red-500/5" :
                            hasHigh ? "border-orange-500/30 bg-orange-500/5" :
                            catFindings.length > 0 ? "border-yellow-500/30 bg-yellow-500/5" :
                            "border-emerald-500/30 bg-emerald-500/5"
                          }`}
                        >
                          <span className="text-lg">{cat.icon}</span>
                          <div className="flex-1 min-w-0">
                            <div className="text-sm font-medium text-zinc-200 truncate">{cat.name}</div>
                            <div className="text-xs text-zinc-500">
                              {passed ? (
                                <span className="text-emerald-400">✓ Passed</span>
                              ) : (
                                <span className={hasCritical ? "text-red-400" : hasHigh ? "text-orange-400" : "text-yellow-400"}>
                                  {catFindings.length} finding{catFindings.length !== 1 ? "s" : ""}
                                </span>
                              )}
                            </div>
                          </div>
                          {passed ? (
                            <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
                          ) : (
                            <AlertTriangle className={`h-4 w-4 shrink-0 ${hasCritical ? "text-red-400" : hasHigh ? "text-orange-400" : "text-yellow-400"}`} />
                          )}
                        </div>
                      );
                    })}
                  </div>
                </CardContent>
              </Card>

              {/* Metadata */}
              <Card className="border-zinc-700/50 bg-zinc-900/50">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-medium text-zinc-300">Assessment Metadata</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                    <div>
                      <span className="text-zinc-500">Domain</span>
                      <div className="text-zinc-200 font-mono">{report.domain}</div>
                    </div>
                    <div>
                      <span className="text-zinc-500">Primary NS</span>
                      <div className="text-zinc-200 font-mono text-xs">{report.metadata.primaryNs || "N/A"}</div>
                    </div>
                    <div>
                      <span className="text-zinc-500">Response Time</span>
                      <div className="text-zinc-200">{report.metadata.responseTimeMs}ms</div>
                    </div>
                    <div>
                      <span className="text-zinc-500">Scanned</span>
                      <div className="text-zinc-200">{new Date(report.scanTimestamp).toLocaleString()}</div>
                    </div>
                  </div>
                  {report.metadata.nameservers?.length > 0 && (
                    <div className="mt-3 pt-3 border-t border-zinc-700/50">
                      <span className="text-xs text-zinc-500">Nameservers:</span>
                      <div className="flex flex-wrap gap-1.5 mt-1">
                        {report.metadata.nameservers.map((ns: string, i: number) => (
                          <Badge key={i} variant="outline" className="text-xs font-mono border-zinc-600">{ns}</Badge>
                        ))}
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            {/* ─── Findings Sub-Tab ─── */}
            <TabsContent value="findings" className="space-y-4 mt-4">
              {report.findings.length === 0 ? (
                <Card className="border-emerald-500/20 bg-emerald-500/5">
                  <CardContent className="py-8 text-center">
                    <CheckCircle2 className="h-10 w-10 text-emerald-400 mx-auto mb-3" />
                    <p className="text-emerald-300 font-medium">No DNS security findings</p>
                    <p className="text-sm text-zinc-400 mt-1">All 15 security checks passed without issues.</p>
                  </CardContent>
                </Card>
              ) : (
                <>
                  {/* Severity filter summary */}
                  <div className="flex items-center gap-3 flex-wrap">
                    <span className="text-sm text-zinc-400">Filter:</span>
                    {Object.entries(severityCounts).filter(([k, v]) => k !== "totalFindings" && (v as number) > 0).map(([sev, count]) => (
                      <Badge key={sev} className={`${SEVERITY_COLORS[sev]} border cursor-default`}>
                        {sev}: {count as number}
                      </Badge>
                    ))}
                  </div>

                  {/* Findings list grouped by category */}
                  {Object.entries(findingsByCategory).map(([category, findings]) => (
                    <Card key={category} className="border-zinc-700/50 bg-zinc-900/50">
                      <CardHeader className="pb-2">
                        <CardTitle className="text-sm font-medium text-zinc-300 flex items-center gap-2">
                          <span>{CATEGORY_ICONS[category] || "🔍"}</span>
                          {category.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase())}
                          <Badge variant="secondary" className="ml-auto text-xs">{(findings as any[]).length}</Badge>
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="space-y-2">
                        {(findings as any[]).map((finding: any) => (
                          <Collapsible
                            key={finding.id}
                            open={expandedFindings.has(finding.id)}
                            onOpenChange={() => toggleFinding(finding.id)}
                          >
                            <CollapsibleTrigger className="w-full">
                              <div className="flex items-center gap-3 p-3 rounded-lg border border-zinc-700/50 hover:border-zinc-600/50 transition-colors cursor-pointer">
                                <Badge className={`${SEVERITY_COLORS[finding.severity]} border text-xs shrink-0`}>
                                  {finding.severity}
                                </Badge>
                                <div className="flex-1 text-left min-w-0">
                                  <div className="text-sm font-medium text-zinc-200 truncate">{finding.title}</div>
                                  {finding.affectedRecord && (
                                    <div className="text-xs text-zinc-500 font-mono mt-0.5">{finding.affectedRecord}</div>
                                  )}
                                </div>
                                {finding.mitreAttackId && (
                                  <Badge variant="outline" className="text-xs border-purple-500/30 text-purple-400 shrink-0">
                                    {finding.mitreAttackId}
                                  </Badge>
                                )}
                                {finding.cvssScore && (
                                  <Badge variant="outline" className="text-xs border-zinc-600 shrink-0">
                                    CVSS {finding.cvssScore.toFixed(1)}
                                  </Badge>
                                )}
                                <ChevronDown className={`h-4 w-4 text-zinc-500 shrink-0 transition-transform ${expandedFindings.has(finding.id) ? "rotate-180" : ""}`} />
                              </div>
                            </CollapsibleTrigger>
                            <CollapsibleContent>
                              <div className="ml-4 mt-2 p-4 rounded-lg bg-zinc-800/50 border border-zinc-700/30 space-y-3">
                                <div>
                                  <div className="text-xs font-medium text-zinc-400 uppercase mb-1">Description</div>
                                  <p className="text-sm text-zinc-300">{finding.description}</p>
                                </div>
                                {finding.evidence && (
                                  <div>
                                    <div className="text-xs font-medium text-zinc-400 uppercase mb-1">Evidence</div>
                                    <pre className="text-xs text-zinc-400 bg-zinc-900/50 p-2 rounded font-mono overflow-x-auto whitespace-pre-wrap">{finding.evidence}</pre>
                                  </div>
                                )}
                                <div>
                                  <div className="text-xs font-medium text-zinc-400 uppercase mb-1">Remediation</div>
                                  <p className="text-sm text-emerald-300/80">{finding.remediation}</p>
                                </div>
                                <div className="flex flex-wrap gap-2 pt-2 border-t border-zinc-700/30">
                                  {finding.mitreAttackId && (
                                    <TooltipProvider>
                                      <Tooltip>
                                        <TooltipTrigger>
                                          <Badge variant="outline" className="text-xs border-purple-500/30 text-purple-400">
                                            <Fingerprint className="h-3 w-3 mr-1" />
                                            {finding.mitreAttackId}
                                          </Badge>
                                        </TooltipTrigger>
                                        <TooltipContent><p>{finding.mitreAttackName}</p></TooltipContent>
                                      </Tooltip>
                                    </TooltipProvider>
                                  )}
                                  {finding.cwe && (
                                    <Badge variant="outline" className="text-xs border-zinc-600">{finding.cwe}</Badge>
                                  )}
                                  {finding.cvssVector && (
                                    <Badge variant="outline" className="text-xs border-zinc-600 font-mono">{finding.cvssVector}</Badge>
                                  )}
                                  {finding.recordType && (
                                    <Badge variant="outline" className="text-xs border-cyan-500/30 text-cyan-400">{finding.recordType}</Badge>
                                  )}
                                </div>
                                {finding.references && finding.references.length > 0 && (
                                  <div className="pt-2">
                                    <div className="text-xs font-medium text-zinc-400 uppercase mb-1">References</div>
                                    <div className="flex flex-col gap-1">
                                      {finding.references.map((ref: string, i: number) => (
                                        <a key={i} href={ref} target="_blank" rel="noopener noreferrer" className="text-xs text-cyan-400 hover:underline flex items-center gap-1">
                                          <ExternalLink className="h-3 w-3" />{ref}
                                        </a>
                                      ))}
                                    </div>
                                  </div>
                                )}
                              </div>
                            </CollapsibleContent>
                          </Collapsible>
                        ))}
                      </CardContent>
                    </Card>
                  ))}
                </>
              )}
            </TabsContent>

            {/* ─── DNS Records Sub-Tab ─── */}
            <TabsContent value="records" className="space-y-4 mt-4">
              <Card className="border-zinc-700/50 bg-zinc-900/50">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-medium text-zinc-300">DNS Records ({report.records.length})</CardTitle>
                  <CardDescription className="text-xs text-zinc-500">All discovered DNS records with TTL values</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b border-zinc-700/50">
                          <th className="text-left py-2 px-3 text-xs font-medium text-zinc-400">Type</th>
                          <th className="text-left py-2 px-3 text-xs font-medium text-zinc-400">Name</th>
                          <th className="text-left py-2 px-3 text-xs font-medium text-zinc-400">Value</th>
                          <th className="text-left py-2 px-3 text-xs font-medium text-zinc-400">TTL</th>
                          <th className="text-left py-2 px-3 text-xs font-medium text-zinc-400">Priority</th>
                        </tr>
                      </thead>
                      <tbody>
                        {report.records.map((rec: any, i: number) => (
                          <tr key={i} className="border-b border-zinc-800/50 hover:bg-zinc-800/30">
                            <td className="py-2 px-3">
                              <Badge variant="outline" className="text-xs font-mono border-cyan-500/30 text-cyan-400">{rec.type}</Badge>
                            </td>
                            <td className="py-2 px-3 font-mono text-xs text-zinc-300 max-w-[200px] truncate">{rec.name}</td>
                            <td className="py-2 px-3 font-mono text-xs text-zinc-400 max-w-[300px] truncate">{rec.value}</td>
                            <td className="py-2 px-3 text-xs text-zinc-500">{rec.ttl != null ? `${rec.ttl}s` : "—"}</td>
                            <td className="py-2 px-3 text-xs text-zinc-500">{rec.priority != null ? rec.priority : "—"}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  {report.records.length === 0 && (
                    <p className="text-center text-zinc-500 py-4">No DNS records discovered</p>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            {/* ─── DNSSEC Sub-Tab ─── */}
            <TabsContent value="dnssec" className="space-y-4 mt-4">
              <Card className="border-zinc-700/50 bg-zinc-900/50">
                <CardHeader>
                  <CardTitle className="text-sm font-medium text-zinc-300 flex items-center gap-2">
                    {report.dnssec.enabled ? (
                      <ShieldCheck className="h-5 w-5 text-emerald-400" />
                    ) : (
                      <ShieldX className="h-5 w-5 text-red-400" />
                    )}
                    DNSSEC Status
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  {/* Status grid */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="p-3 rounded-lg bg-zinc-800/50 border border-zinc-700/30">
                      <div className="text-xs text-zinc-500 mb-1">Enabled</div>
                      <div className={report.dnssec.enabled ? "text-emerald-400 font-medium" : "text-red-400 font-medium"}>
                        {report.dnssec.enabled ? "Yes" : "No"}
                      </div>
                    </div>
                    <div className="p-3 rounded-lg bg-zinc-800/50 border border-zinc-700/30">
                      <div className="text-xs text-zinc-500 mb-1">Delegation Signed</div>
                      <div className={report.dnssec.delegationSigned ? "text-emerald-400 font-medium" : "text-zinc-400 font-medium"}>
                        {report.dnssec.delegationSigned ? "Yes" : "No"}
                      </div>
                    </div>
                    <div className="p-3 rounded-lg bg-zinc-800/50 border border-zinc-700/30">
                      <div className="text-xs text-zinc-500 mb-1">RRSIG Present</div>
                      <div className={report.dnssec.rrsigPresent ? "text-emerald-400 font-medium" : "text-zinc-400 font-medium"}>
                        {report.dnssec.rrsigPresent ? "Yes" : "No"}
                      </div>
                    </div>
                    <div className="p-3 rounded-lg bg-zinc-800/50 border border-zinc-700/30">
                      <div className="text-xs text-zinc-500 mb-1">Algorithm Strength</div>
                      <div className={`font-medium ${
                        report.dnssec.algorithmStrength === "strong" ? "text-emerald-400" :
                        report.dnssec.algorithmStrength === "acceptable" ? "text-yellow-400" :
                        report.dnssec.algorithmStrength === "weak" ? "text-red-400" : "text-zinc-400"
                      }`}>
                        {report.dnssec.algorithmStrength || "N/A"}
                      </div>
                    </div>
                  </div>

                  {/* Chain of Trust */}
                  <div className="p-3 rounded-lg bg-zinc-800/50 border border-zinc-700/30">
                    <div className="text-xs font-medium text-zinc-400 uppercase mb-2">Chain of Trust</div>
                    <div className="flex items-center gap-2">
                      {report.dnssec.chainOfTrustValid ? (
                        <><CheckCircle2 className="h-4 w-4 text-emerald-400" /><span className="text-sm text-emerald-300">Valid — full chain verified from root to domain</span></>
                      ) : report.dnssec.enabled ? (
                        <><AlertTriangle className="h-4 w-4 text-yellow-400" /><span className="text-sm text-yellow-300">Chain of trust could not be fully validated</span></>
                      ) : (
                        <><XCircle className="h-4 w-4 text-zinc-500" /><span className="text-sm text-zinc-400">DNSSEC not enabled — no chain of trust to validate</span></>
                      )}
                    </div>
                  </div>

                  {/* DS Records */}
                  {report.dnssec.dsRecords && report.dnssec.dsRecords.length > 0 && (
                    <div>
                      <div className="text-xs font-medium text-zinc-400 uppercase mb-2">DS Records (Delegation Signer)</div>
                      <div className="space-y-2">
                        {report.dnssec.dsRecords.map((ds: any, i: number) => (
                          <div key={i} className="p-2 rounded bg-zinc-800/30 border border-zinc-700/20 text-xs font-mono">
                            <span className="text-cyan-400">Key Tag:</span> {ds.keyTag} |{" "}
                            <span className="text-cyan-400">Algorithm:</span> {ds.algorithmName} ({ds.algorithm}) |{" "}
                            <span className="text-cyan-400">Digest Type:</span> {ds.digestType}
                            <div className="text-zinc-500 mt-1 break-all">Digest: {ds.digest}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* DNSKEY Records */}
                  {report.dnssec.dnskeyRecords && report.dnssec.dnskeyRecords.length > 0 && (
                    <div>
                      <div className="text-xs font-medium text-zinc-400 uppercase mb-2">DNSKEY Records</div>
                      <div className="space-y-2">
                        {report.dnssec.dnskeyRecords.map((key: any, i: number) => (
                          <div key={i} className="p-2 rounded bg-zinc-800/30 border border-zinc-700/20 text-xs font-mono">
                            <span className="text-cyan-400">Flags:</span> {key.flags} ({key.flags === 257 ? "KSK" : key.flags === 256 ? "ZSK" : "Other"}) |{" "}
                            <span className="text-cyan-400">Algorithm:</span> {key.algorithmName} ({key.algorithm})
                            {key.keyLength && <> | <span className="text-cyan-400">Key Length:</span> {key.keyLength} bits</>}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Signature Expiry */}
                  {report.dnssec.signatureExpiry && (
                    <div className="p-3 rounded-lg bg-zinc-800/50 border border-zinc-700/30">
                      <div className="text-xs text-zinc-500 mb-1">Signature Expiry</div>
                      <div className="text-sm text-zinc-200 flex items-center gap-2">
                        <Clock className="h-4 w-4 text-zinc-400" />
                        {report.dnssec.signatureExpiry}
                      </div>
                    </div>
                  )}

                  {/* Issues */}
                  {report.dnssec.issues && report.dnssec.issues.length > 0 && (
                    <div>
                      <div className="text-xs font-medium text-zinc-400 uppercase mb-2">Issues</div>
                      <div className="space-y-1">
                        {report.dnssec.issues.map((issue: string, i: number) => (
                          <div key={i} className="flex items-start gap-2 text-sm">
                            <AlertTriangle className="h-3.5 w-3.5 text-yellow-400 mt-0.5 shrink-0" />
                            <span className="text-yellow-300/80">{issue}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            {/* ─── MITRE ATT&CK Sub-Tab ─── */}
            <TabsContent value="mitre" className="space-y-4 mt-4">
              <Card className="border-zinc-700/50 bg-zinc-900/50">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-medium text-zinc-300 flex items-center gap-2">
                    <Fingerprint className="h-4 w-4 text-purple-400" />
                    MITRE ATT&CK Mapping — DNS Techniques
                  </CardTitle>
                  <CardDescription className="text-xs text-zinc-500">
                    Techniques relevant to DNS-based attack vectors mapped to findings
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {(mitreMapping || []).map((technique: any) => {
                      const relatedFindings = report.findings.filter((f: any) => f.mitreAttackId === technique.id);
                      return (
                        <div
                          key={technique.id}
                          className={`p-3 rounded-lg border ${
                            relatedFindings.length > 0
                              ? "border-purple-500/30 bg-purple-500/5"
                              : "border-zinc-700/30 bg-zinc-800/30"
                          }`}
                        >
                          <div className="flex items-center gap-3">
                            <Badge variant="outline" className="text-xs border-purple-500/30 text-purple-400 font-mono shrink-0">
                              {technique.id}
                            </Badge>
                            <div className="flex-1 min-w-0">
                              <div className="text-sm font-medium text-zinc-200">{technique.name}</div>
                              <div className="text-xs text-zinc-500">{technique.tactic} — {technique.dnsRelevance}</div>
                            </div>
                            {relatedFindings.length > 0 && (
                              <Badge className="bg-purple-500/20 text-purple-300 text-xs shrink-0">
                                {relatedFindings.length} finding{relatedFindings.length !== 1 ? "s" : ""}
                              </Badge>
                            )}
                          </div>
                          {relatedFindings.length > 0 && (
                            <div className="mt-2 pl-[72px] space-y-1">
                              {relatedFindings.map((f: any) => (
                                <div key={f.id} className="text-xs text-zinc-400 flex items-center gap-2">
                                  <Badge className={`${SEVERITY_COLORS[f.severity]} border text-[10px]`}>{f.severity}</Badge>
                                  <span className="truncate">{f.title}</span>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </>
      )}
    </div>
  );
}
