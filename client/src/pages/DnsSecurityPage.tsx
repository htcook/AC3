// @ts-nocheck
import { useState } from "react";
import AppShell from "@/components/AppShell";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Shield, AlertTriangle, Globe, Network, Loader2, CheckCircle2, XCircle,
  RefreshCw, ShieldCheck, ShieldX, ExternalLink, ChevronDown, Fingerprint, Zap, Search
} from "lucide-react";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

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

export default function DnsSecurityPage() {
  const [domain, setDomain] = useState("");
  const [context, setContext] = useState<"di_scan" | "vuln_pentest" | "red_team">("di_scan");
  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set());

  const assessMut = trpc.dnsSecurity.runAssessment.useMutation({
    onSuccess: () => toast.success("DNS security assessment complete"),
    onError: (err: any) => toast.error(`Assessment failed: ${err.message}`),
  });

  const { data: categories } = trpc.dnsSecurity.getCheckCategories.useQuery();
  const { data: mitreMapping } = trpc.dnsSecurity.getMitreMapping.useQuery();
  const { data: fingerprints } = trpc.dnsSecurity.getFingerprints.useQuery();

  const report = assessMut.data;

  const toggleFinding = (id: string) => {
    setExpandedFindings(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const runAssessment = () => {
    if (!domain.trim()) {
      toast.error("Please enter a domain");
      return;
    }
    assessMut.mutate({ domain: domain.trim(), context });
  };

  const findingsByCategory = report?.findings?.reduce((acc: Record<string, any[]>, f: any) => {
    if (!acc[f.category]) acc[f.category] = [];
    acc[f.category].push(f);
    return acc;
  }, {} as Record<string, any[]>) || {};

  return (
    <AppShell>
      <div className="p-6 space-y-6 max-w-7xl mx-auto">
        {/* Page Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-zinc-100 flex items-center gap-3">
              <Shield className="h-7 w-7 text-cyan-400" />
              DNS Security Validator
            </h1>
            <p className="text-sm text-zinc-400 mt-1">
              Comprehensive DNS security assessment — 15 parallel checks, 35+ takeover fingerprints, DNSSEC chain-of-trust validation, MITRE ATT&CK mapping
            </p>
          </div>
          {fingerprints && (
            <Badge variant="outline" className="border-cyan-500/30 text-cyan-400">
              {fingerprints.totalServices} takeover fingerprints loaded
            </Badge>
          )}
        </div>

        {/* Domain Input */}
        <Card className="border-zinc-700/50 bg-zinc-900/50">
          <CardContent className="pt-4 pb-4">
            <div className="flex gap-3 items-end">
              <div className="flex-1">
                <label className="text-xs text-zinc-400 mb-1 block">Target Domain</label>
                <Input
                  placeholder="example.com"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && runAssessment()}
                  className="bg-zinc-800/50 border-zinc-700"
                />
              </div>
              <div className="w-48">
                <label className="text-xs text-zinc-400 mb-1 block">Context</label>
                <Select value={context} onValueChange={(v: any) => setContext(v)}>
                  <SelectTrigger className="bg-zinc-800/50 border-zinc-700">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="di_scan">Domain Intelligence</SelectItem>
                    <SelectItem value="vuln_pentest">Vuln/Pentest</SelectItem>
                    <SelectItem value="red_team">Red Team</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <Button
                onClick={runAssessment}
                disabled={assessMut.isPending || !domain.trim()}
                className="bg-cyan-600 hover:bg-cyan-700"
              >
                {assessMut.isPending ? (
                  <><Loader2 className="h-4 w-4 animate-spin mr-2" /> Scanning...</>
                ) : (
                  <><Search className="h-4 w-4 mr-2" /> Assess</>
                )}
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Results */}
        {!report && !assessMut.isPending && (
          <Card className="border-zinc-700/50 bg-zinc-900/50">
            <CardContent className="py-16 text-center">
              <Shield className="h-16 w-16 text-zinc-700 mx-auto mb-4" />
              <p className="text-zinc-400 text-lg mb-2">Enter a domain to begin assessment</p>
              <p className="text-sm text-zinc-500 max-w-md mx-auto">
                The DNS Security Validator performs 15 parallel checks including dangling DNS detection,
                DNSSEC validation, zone transfer testing, cache poisoning susceptibility, and more.
              </p>
            </CardContent>
          </Card>
        )}

        {assessMut.isPending && (
          <Card className="border-cyan-500/20 bg-cyan-500/5">
            <CardContent className="py-12 text-center">
              <Loader2 className="h-10 w-10 animate-spin text-cyan-400 mx-auto mb-4" />
              <p className="text-cyan-300 font-medium">Running DNS Security Assessment...</p>
              <p className="text-sm text-zinc-400 mt-1">Performing 15 parallel security checks on {domain}</p>
            </CardContent>
          </Card>
        )}

        {report && (
          <>
            {/* Summary Cards */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <Card className="border-zinc-700/50 bg-zinc-900/50">
                <CardContent className="pt-4 pb-4">
                  <div className="text-sm text-zinc-400 mb-1">Overall Risk</div>
                  <div className={`text-2xl font-bold uppercase ${RISK_COLORS[report.summary.overallRisk] || "text-zinc-300"}`}>
                    {report.summary.overallRisk}
                  </div>
                  <div className="text-xs text-zinc-500 mt-1">{report.domain}</div>
                </CardContent>
              </Card>
              <Card className="border-zinc-700/50 bg-zinc-900/50">
                <CardContent className="pt-4 pb-4">
                  <div className="text-sm text-zinc-400 mb-1">Total Findings</div>
                  <div className="text-2xl font-bold text-zinc-100">{report.summary.totalFindings}</div>
                  <div className="flex gap-1.5 mt-1 flex-wrap">
                    {report.summary.critical > 0 && <Badge className="bg-red-500/20 text-red-400 text-xs">{report.summary.critical} Crit</Badge>}
                    {report.summary.high > 0 && <Badge className="bg-orange-500/20 text-orange-400 text-xs">{report.summary.high} High</Badge>}
                    {report.summary.medium > 0 && <Badge className="bg-yellow-500/20 text-yellow-400 text-xs">{report.summary.medium} Med</Badge>}
                    {report.summary.low > 0 && <Badge className="bg-blue-500/20 text-blue-400 text-xs">{report.summary.low} Low</Badge>}
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
                  <div className="text-xs text-zinc-500 mt-1">
                    {report.metadata.responseTimeMs}ms response time
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Tabs */}
            <Tabs defaultValue="findings">
              <TabsList className="bg-zinc-800/50 border border-zinc-700/50">
                <TabsTrigger value="findings">Findings ({report.summary.totalFindings})</TabsTrigger>
                <TabsTrigger value="records">DNS Records ({report.records.length})</TabsTrigger>
                <TabsTrigger value="dnssec">DNSSEC</TabsTrigger>
                <TabsTrigger value="checks">Check Results</TabsTrigger>
                <TabsTrigger value="mitre">MITRE ATT&CK</TabsTrigger>
                <TabsTrigger value="monitoring">Monitoring</TabsTrigger>
              </TabsList>

              {/* Findings Tab */}
              <TabsContent value="findings" className="space-y-4 mt-4">
                {report.findings.length === 0 ? (
                  <Card className="border-emerald-500/20 bg-emerald-500/5">
                    <CardContent className="py-8 text-center">
                      <CheckCircle2 className="h-10 w-10 text-emerald-400 mx-auto mb-3" />
                      <p className="text-emerald-300 font-medium">No DNS security findings</p>
                      <p className="text-sm text-zinc-400 mt-1">All 15 security checks passed.</p>
                    </CardContent>
                  </Card>
                ) : (
                  Object.entries(findingsByCategory).map(([category, findings]) => (
                    <Card key={category} className="border-zinc-700/50 bg-zinc-900/50">
                      <CardHeader className="pb-2">
                        <CardTitle className="text-sm font-medium text-zinc-300 flex items-center gap-2">
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
                                    <Badge variant="outline" className="text-xs border-purple-500/30 text-purple-400">
                                      <Fingerprint className="h-3 w-3 mr-1" />{finding.mitreAttackId}
                                    </Badge>
                                  )}
                                  {finding.cwe && <Badge variant="outline" className="text-xs border-zinc-600">{finding.cwe}</Badge>}
                                  {finding.cvssVector && <Badge variant="outline" className="text-xs border-zinc-600 font-mono">{finding.cvssVector}</Badge>}
                                </div>
                                {finding.references?.length > 0 && (
                                  <div className="pt-2">
                                    <div className="text-xs font-medium text-zinc-400 uppercase mb-1">References</div>
                                    {finding.references.map((ref: string, i: number) => (
                                      <a key={i} href={ref} target="_blank" rel="noopener noreferrer" className="text-xs text-cyan-400 hover:underline flex items-center gap-1">
                                        <ExternalLink className="h-3 w-3" />{ref}
                                      </a>
                                    ))}
                                  </div>
                                )}
                              </div>
                            </CollapsibleContent>
                          </Collapsible>
                        ))}
                      </CardContent>
                    </Card>
                  ))
                )}
              </TabsContent>

              {/* DNS Records Tab */}
              <TabsContent value="records" className="mt-4">
                <Card className="border-zinc-700/50 bg-zinc-900/50">
                  <CardContent className="pt-4">
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
                  </CardContent>
                </Card>
              </TabsContent>

              {/* DNSSEC Tab */}
              <TabsContent value="dnssec" className="space-y-4 mt-4">
                <Card className="border-zinc-700/50 bg-zinc-900/50">
                  <CardHeader>
                    <CardTitle className="text-sm font-medium text-zinc-300 flex items-center gap-2">
                      {report.dnssec.enabled ? <ShieldCheck className="h-5 w-5 text-emerald-400" /> : <ShieldX className="h-5 w-5 text-red-400" />}
                      DNSSEC Chain-of-Trust
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                      {[
                        { label: "Enabled", value: report.dnssec.enabled },
                        { label: "Delegation Signed", value: report.dnssec.delegationSigned },
                        { label: "RRSIG Present", value: report.dnssec.rrsigPresent },
                        { label: "Chain Valid", value: report.dnssec.chainOfTrustValid },
                      ].map((item) => (
                        <div key={item.label} className="p-3 rounded-lg bg-zinc-800/50 border border-zinc-700/30">
                          <div className="text-xs text-zinc-500 mb-1">{item.label}</div>
                          <div className={item.value ? "text-emerald-400 font-medium" : "text-red-400 font-medium"}>
                            {item.value ? "Yes" : "No"}
                          </div>
                        </div>
                      ))}
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
                    {report.dnssec.dsRecords?.length > 0 && (
                      <div>
                        <div className="text-xs font-medium text-zinc-400 uppercase mb-2">DS Records</div>
                        {report.dnssec.dsRecords.map((ds: any, i: number) => (
                          <div key={i} className="p-2 rounded bg-zinc-800/30 border border-zinc-700/20 text-xs font-mono mb-1">
                            Key Tag: {ds.keyTag} | Algorithm: {ds.algorithmName} ({ds.algorithm}) | Digest Type: {ds.digestType}
                          </div>
                        ))}
                      </div>
                    )}
                    {report.dnssec.issues?.length > 0 && (
                      <div>
                        <div className="text-xs font-medium text-zinc-400 uppercase mb-2">Issues</div>
                        {report.dnssec.issues.map((issue: string, i: number) => (
                          <div key={i} className="flex items-start gap-2 text-sm text-yellow-300/80">
                            <AlertTriangle className="h-3.5 w-3.5 mt-0.5 shrink-0" />{issue}
                          </div>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>
              </TabsContent>

              {/* Check Results Tab */}
              <TabsContent value="checks" className="mt-4">
                <Card className="border-zinc-700/50 bg-zinc-900/50">
                  <CardContent className="pt-4">
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                      {(categories || []).map((cat: any) => {
                        const catFindings = findingsByCategory[cat.id] || [];
                        const passed = catFindings.length === 0;
                        const hasCritical = catFindings.some((f: any) => f.severity === "critical");
                        const hasHigh = catFindings.some((f: any) => f.severity === "high");
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
                              <div className="text-xs text-zinc-500">{cat.description}</div>
                            </div>
                            {passed ? (
                              <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
                            ) : (
                              <Badge className={`${hasCritical ? "bg-red-500/20 text-red-400" : hasHigh ? "bg-orange-500/20 text-orange-400" : "bg-yellow-500/20 text-yellow-400"} text-xs`}>
                                {catFindings.length}
                              </Badge>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>

              {/* MITRE ATT&CK Tab */}
              <TabsContent value="mitre" className="mt-4">
                <Card className="border-zinc-700/50 bg-zinc-900/50">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-sm font-medium text-zinc-300 flex items-center gap-2">
                      <Fingerprint className="h-4 w-4 text-purple-400" />
                      MITRE ATT&CK Mapping
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    {(mitreMapping || []).map((technique: any) => {
                      const relatedFindings = report.findings.filter((f: any) => f.mitreAttackId === technique.id);
                      return (
                        <div
                          key={technique.id}
                          className={`p-3 rounded-lg border ${
                            relatedFindings.length > 0 ? "border-purple-500/30 bg-purple-500/5" : "border-zinc-700/30 bg-zinc-800/30"
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
                              <Badge className="bg-purple-500/20 text-purple-300 text-xs">
                                {relatedFindings.length} hit{relatedFindings.length !== 1 ? "s" : ""}
                              </Badge>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </CardContent>
                </Card>
              </TabsContent>

              {/* Monitoring Tab */}
              <TabsContent value="monitoring" className="mt-4">
                <DnsMonitoringConfig domain={domain} />
              </TabsContent>
            </Tabs>
          </>
        )}
      </div>
    </AppShell>
  );
}

// ─── DNS Monitoring Configuration Component ────────────────────────────────────────
function DnsMonitoringConfig({ domain }: { domain: string }) {
  const { data: config, isLoading } = trpc.dnsSecurity.getMonitoringConfig.useQuery(
    { domain },
    { enabled: !!domain }
  );
  const { data: allDomains } = trpc.dnsSecurity.getMonitoredDomains.useQuery();
  const updateConfig = trpc.dnsSecurity.updateMonitoringConfig.useMutation({
    onSuccess: () => toast.success("Monitoring config updated"),
    onError: (err: any) => toast.error(err.message),
  });
  const utils = trpc.useUtils();

  const handleToggle = (field: string, value: boolean) => {
    updateConfig.mutate(
      { domain, [field]: value },
      { onSuccess: () => utils.dnsSecurity.getMonitoringConfig.invalidate({ domain }) }
    );
  };

  const handleIntervalChange = (hours: number) => {
    updateConfig.mutate(
      { domain, intervalHours: hours },
      { onSuccess: () => utils.dnsSecurity.getMonitoringConfig.invalidate({ domain }) }
    );
  };

  return (
    <div className="space-y-4">
      {/* Current Domain Config */}
      <Card className="border-zinc-700/50 bg-zinc-900/50">
        <CardHeader>
          <CardTitle className="text-sm font-display tracking-wider flex items-center gap-2">
            <Shield className="w-4 h-4 text-primary" />
            MONITORING CONFIG: {domain.toUpperCase()}
          </CardTitle>
          <CardDescription className="text-xs">
            Configure automated DNS security monitoring for this domain
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {isLoading ? (
            <div className="flex items-center justify-center py-6">
              <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
            </div>
          ) : config ? (
            <>
              {/* Enable/Disable */}
              <div className="flex items-center justify-between p-3 bg-zinc-800/50 rounded border border-zinc-700/30">
                <div>
                  <p className="text-sm font-medium">Automated Monitoring</p>
                  <p className="text-xs text-muted-foreground">Run DNS security checks on a schedule</p>
                </div>
                <button
                  onClick={() => handleToggle('enabled', !config.enabled)}
                  className={`relative w-11 h-6 rounded-full transition-colors ${
                    config.enabled ? 'bg-emerald-500' : 'bg-zinc-600'
                  }`}
                >
                  <span className={`absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-white transition-transform ${
                    config.enabled ? 'translate-x-5' : 'translate-x-0'
                  }`} />
                </button>
              </div>

              {/* Interval */}
              <div className="flex items-center justify-between p-3 bg-zinc-800/50 rounded border border-zinc-700/30">
                <div>
                  <p className="text-sm font-medium">Check Interval</p>
                  <p className="text-xs text-muted-foreground">How often to re-assess DNS security</p>
                </div>
                <select
                  value={config.intervalHours || 24}
                  onChange={(e) => handleIntervalChange(Number(e.target.value))}
                  className="bg-zinc-700 border border-zinc-600 rounded px-3 py-1.5 text-xs"
                >
                  <option value={6}>Every 6 hours</option>
                  <option value={12}>Every 12 hours</option>
                  <option value={24}>Every 24 hours</option>
                  <option value={48}>Every 48 hours</option>
                  <option value={72}>Every 72 hours</option>
                  <option value={168}>Weekly</option>
                </select>
              </div>

              {/* Alert Settings */}
              <div className="space-y-2">
                <p className="text-xs font-display tracking-wider text-muted-foreground">ALERT SETTINGS</p>
                {[
                  { field: 'alertOnNewCritical', label: 'Alert on new critical findings', value: config.alertOnNewCritical },
                  { field: 'alertOnNewHigh', label: 'Alert on new high findings', value: config.alertOnNewHigh },
                  { field: 'alertOnDnsChange', label: 'Alert on DNS record changes', value: config.alertOnDnsChange },
                ].map(({ field, label, value }) => (
                  <div key={field} className="flex items-center justify-between p-2 bg-zinc-800/30 rounded">
                    <span className="text-xs">{label}</span>
                    <button
                      onClick={() => handleToggle(field, !value)}
                      className={`relative w-9 h-5 rounded-full transition-colors ${
                        value ? 'bg-emerald-500' : 'bg-zinc-600'
                      }`}
                    >
                      <span className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white transition-transform ${
                        value ? 'translate-x-4' : 'translate-x-0'
                      }`} />
                    </button>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <p className="text-xs text-muted-foreground text-center py-4">No config available</p>
          )}
        </CardContent>
      </Card>

      {/* All Monitored Domains */}
      {allDomains && allDomains.length > 0 && (
        <Card className="border-zinc-700/50 bg-zinc-900/50">
          <CardHeader>
            <CardTitle className="text-sm font-display tracking-wider flex items-center gap-2">
              <Globe className="w-4 h-4 text-cyan-400" />
              ALL MONITORED DOMAINS ({allDomains.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2 max-h-64 overflow-y-auto">
              {allDomains.map((d: any) => (
                <div key={d.domain} className="flex items-center justify-between p-2 bg-zinc-800/30 rounded border border-zinc-700/20">
                  <div className="flex items-center gap-2">
                    <div className={`w-2 h-2 rounded-full ${d.enabled ? 'bg-emerald-400' : 'bg-zinc-500'}`} />
                    <span className="text-xs font-mono">{d.domain}</span>
                  </div>
                  <div className="flex items-center gap-2 text-[10px] text-muted-foreground">
                    <span>Every {d.intervalHours || 24}h</span>
                    {d.lastCheckedAt && <span>• Last: {new Date(d.lastCheckedAt).toLocaleDateString()}</span>}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
