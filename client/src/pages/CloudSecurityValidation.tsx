import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { toast } from "sonner";
import {
  Shield, Cloud, Server, Database, Network, Eye, AlertTriangle, CheckCircle2,
  XCircle, Minus, ChevronDown, ChevronRight, BarChart3, FileText, Loader2,
} from "lucide-react";
import AppShell from "@/components/AppShell";

type Provider = "aws" | "azure" | "gcp";
type Domain = "iam" | "networking" | "storage" | "compute" | "logging";

const PROVIDER_META: Record<Provider, { label: string; color: string; icon: React.ReactNode }> = {
  aws: { label: "AWS", color: "text-amber-400", icon: <Cloud className="h-5 w-5 text-amber-400" /> },
  azure: { label: "Azure", color: "text-blue-400", icon: <Cloud className="h-5 w-5 text-blue-400" /> },
  gcp: { label: "GCP", color: "text-red-400", icon: <Cloud className="h-5 w-5 text-red-400" /> },
};

const DOMAIN_META: Record<Domain, { label: string; icon: React.ReactNode }> = {
  iam: { label: "Identity & Access", icon: <Shield className="h-4 w-4" /> },
  networking: { label: "Networking", icon: <Network className="h-4 w-4" /> },
  storage: { label: "Storage", icon: <Database className="h-4 w-4" /> },
  compute: { label: "Compute", icon: <Server className="h-4 w-4" /> },
  logging: { label: "Logging & Monitoring", icon: <Eye className="h-4 w-4" /> },
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  info: "bg-slate-500/20 text-slate-400 border-slate-500/30",
};

export default function CloudSecurityValidation() {
  const [provider, setProvider] = useState<Provider>("aws");
  const [accountId, setAccountId] = useState("");
  const [accountAlias, setAccountAlias] = useState("");
  const [selectedDomains, setSelectedDomains] = useState<Domain[]>([]);
  const [assessment, setAssessment] = useState<any>(null);
  const [expandedChecks, setExpandedChecks] = useState<Set<string>>(new Set());
  const [filterSeverity, setFilterSeverity] = useState<string>("all");
  const [filterStatus, setFilterStatus] = useState<string>("all");

  const { data: providerStats } = trpc.cloudSecurityValidation.getProviderStats.useQuery();
  const { data: checksData } = trpc.cloudSecurityValidation.listChecks.useQuery({ provider });
  const { data: domainBreakdown } = trpc.cloudSecurityValidation.getDomainBreakdown.useQuery({ provider });
  const { data: mitreCoverage } = trpc.cloudSecurityValidation.getMitreCoverage.useQuery({ provider });

  const runAssessmentMutation = trpc.cloudSecurityValidation.runAssessment.useMutation({
    onSuccess: (data) => {
      setAssessment(data);
      toast.success(`Assessment complete — ${data.overallScore}% compliance score`);
    },
    onError: (err) => toast.error(err.message),
  });

  const toggleDomain = (domain: Domain) => {
    setSelectedDomains(prev =>
      prev.includes(domain) ? prev.filter(d => d !== domain) : [...prev, domain]
    );
  };

  const toggleCheck = (checkId: string) => {
    setExpandedChecks(prev => {
      const next = new Set(prev);
      next.has(checkId) ? next.delete(checkId) : next.add(checkId);
      return next;
    });
  };

  const handleRunAssessment = () => {
    if (!accountId.trim()) {
      toast.error("Account ID is required");
      return;
    }
    runAssessmentMutation.mutate({
      provider,
      accountId: accountId.trim(),
      accountAlias: accountAlias.trim(),
      domains: selectedDomains.length > 0 ? selectedDomains : undefined,
    });
  };

  const filteredResults = useMemo(() => {
    if (!assessment?.results) return [];
    return assessment.results.filter((r: any) => {
      if (filterStatus !== "all" && r.status !== filterStatus) return false;
      if (filterSeverity !== "all") {
        const check = checksData?.checks.find((c: any) => c.id === r.checkId);
        if (check && check.severity !== filterSeverity) return false;
      }
      return true;
    });
  }, [assessment, filterStatus, filterSeverity, checksData]);

  const currentProviderStats = providerStats?.providers.find(p => p.provider === provider);

  return (
      <AppShell activePath="/cloud-security-validation">
      <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Shield className="h-7 w-7 text-cyan-400" />
          Cloud Security Validation
        </h1>
        <p className="text-muted-foreground mt-1">
          CIS Benchmark-aligned misconfiguration testing across AWS, Azure, and GCP
        </p>
      </div>

      {/* Provider Selector + Stats */}
      <div className="grid grid-cols-3 gap-4">
        {(["aws", "azure", "gcp"] as Provider[]).map(p => {
          const meta = PROVIDER_META[p];
          const stats = providerStats?.providers.find(s => s.provider === p);
          return (
            <Card
              key={p}
              className={`cursor-pointer transition-all ${provider === p ? "ring-2 ring-cyan-500/50 bg-cyan-500/5" : "hover:bg-muted/30"}`}
              onClick={() => { setProvider(p); setAssessment(null); }}
            >
              <CardContent className="p-4">
                <div className="flex items-center gap-3">
                  {meta.icon}
                  <div>
                    <div className={`font-semibold ${meta.color}`}>{meta.label}</div>
                    <div className="text-xs text-muted-foreground">
                      {stats?.totalChecks || 0} checks · {stats?.cisBenchmarkVersion || ""}
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      <Tabs defaultValue="assess" className="space-y-4">
        <TabsList>
          <TabsTrigger value="assess">Run Assessment</TabsTrigger>
          <TabsTrigger value="checks">Check Catalog ({checksData?.total || 0})</TabsTrigger>
          <TabsTrigger value="coverage">MITRE Coverage</TabsTrigger>
        </TabsList>

        {/* Assessment Tab */}
        <TabsContent value="assess" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Configure Assessment</CardTitle>
              <CardDescription>
                Run CIS Benchmark checks against your {PROVIDER_META[provider].label} environment
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-sm font-medium mb-1 block">Account ID *</label>
                  <Input
                    placeholder={provider === "aws" ? "123456789012" : provider === "azure" ? "subscription-id" : "project-id"}
                    value={accountId}
                    onChange={e => setAccountId(e.target.value)}
                  />
                </div>
                <div>
                  <label className="text-sm font-medium mb-1 block">Account Alias</label>
                  <Input
                    placeholder="Production, Staging, etc."
                    value={accountAlias}
                    onChange={e => setAccountAlias(e.target.value)}
                  />
                </div>
              </div>

              {/* Domain Selection */}
              <div>
                <label className="text-sm font-medium mb-2 block">Domains (leave empty for all)</label>
                <div className="flex flex-wrap gap-2">
                  {(Object.entries(DOMAIN_META) as [Domain, { label: string; icon: React.ReactNode }][]).map(([key, meta]) => {
                    const domainStats = domainBreakdown?.domains.find(d => d.domain === key);
                    return (
                      <Button
                        key={key}
                        variant={selectedDomains.includes(key) ? "default" : "outline"}
                        size="sm"
                        onClick={() => toggleDomain(key)}
                        className="gap-1.5"
                      >
                        {meta.icon}
                        {meta.label}
                        {domainStats && (
                          <span className="text-xs opacity-70">({domainStats.totalChecks})</span>
                        )}
                      </Button>
                    );
                  })}
                </div>
              </div>

              <Button
                onClick={handleRunAssessment}
                disabled={runAssessmentMutation.isPending}
                className="w-full"
              >
                {runAssessmentMutation.isPending ? (
                  <><Loader2 className="h-4 w-4 animate-spin mr-2" /> Running Assessment...</>
                ) : (
                  <><BarChart3 className="h-4 w-4 mr-2" /> Run {PROVIDER_META[provider].label} Assessment</>
                )}
              </Button>
            </CardContent>
          </Card>

          {/* Assessment Results */}
          {assessment && (
            <div className="space-y-4">
              {/* Score Overview */}
              <div className="grid grid-cols-4 gap-4">
                <Card className="col-span-1">
                  <CardContent className="p-4 text-center">
                    <div className={`text-4xl font-bold ${assessment.overallScore >= 80 ? "text-green-400" : assessment.overallScore >= 50 ? "text-yellow-400" : "text-red-400"}`}>
                      {assessment.overallScore}%
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">Overall Score</div>
                    <Progress value={assessment.overallScore} className="mt-2" />
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="p-4 flex items-center gap-3">
                    <CheckCircle2 className="h-8 w-8 text-green-400" />
                    <div>
                      <div className="text-2xl font-bold">{assessment.passed}</div>
                      <div className="text-xs text-muted-foreground">Passed</div>
                    </div>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="p-4 flex items-center gap-3">
                    <XCircle className="h-8 w-8 text-red-400" />
                    <div>
                      <div className="text-2xl font-bold">{assessment.failed}</div>
                      <div className="text-xs text-muted-foreground">Failed</div>
                    </div>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="p-4 flex items-center gap-3">
                    <Minus className="h-8 w-8 text-slate-400" />
                    <div>
                      <div className="text-2xl font-bold">{assessment.notAssessed}</div>
                      <div className="text-xs text-muted-foreground">Not Assessed</div>
                    </div>
                  </CardContent>
                </Card>
              </div>

              {/* Domain Scores */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm">Domain Scores</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-5 gap-3">
                    {(Object.entries(assessment.domainScores) as [string, any][]).map(([domain, scores]) => (
                      <div key={domain} className="text-center p-3 rounded-lg bg-muted/30">
                        <div className="flex justify-center mb-1">
                          {DOMAIN_META[domain as Domain]?.icon}
                        </div>
                        <div className="text-xs text-muted-foreground mb-1">
                          {DOMAIN_META[domain as Domain]?.label || domain}
                        </div>
                        <div className={`text-lg font-bold ${scores.score >= 80 ? "text-green-400" : scores.score >= 50 ? "text-yellow-400" : "text-red-400"}`}>
                          {scores.score}%
                        </div>
                        <div className="text-xs text-muted-foreground">
                          {scores.passed}/{scores.total}
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              {/* Filters */}
              <div className="flex gap-3">
                <Select value={filterSeverity} onValueChange={setFilterSeverity}>
                  <SelectTrigger className="w-40">
                    <SelectValue placeholder="Severity" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Severities</SelectItem>
                    <SelectItem value="critical">Critical</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="low">Low</SelectItem>
                  </SelectContent>
                </Select>
                <Select value={filterStatus} onValueChange={setFilterStatus}>
                  <SelectTrigger className="w-40">
                    <SelectValue placeholder="Status" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Statuses</SelectItem>
                    <SelectItem value="pass">Passed</SelectItem>
                    <SelectItem value="fail">Failed</SelectItem>
                    <SelectItem value="warning">Warning</SelectItem>
                    <SelectItem value="not_assessed">Not Assessed</SelectItem>
                  </SelectContent>
                </Select>
                <div className="text-sm text-muted-foreground self-center ml-2">
                  Showing {filteredResults.length} of {assessment.results.length} results
                </div>
              </div>

              {/* Results List */}
              <div className="space-y-2">
                {filteredResults.map((result: any) => {
                  const check = checksData?.checks.find((c: any) => c.id === result.checkId);
                  if (!check) return null;
                  const expanded = expandedChecks.has(result.checkId);
                  return (
                    <Card key={result.checkId} className="overflow-hidden">
                      <div
                        className="p-3 flex items-center gap-3 cursor-pointer hover:bg-muted/20"
                        onClick={() => toggleCheck(result.checkId)}
                      >
                        {result.status === "pass" ? (
                          <CheckCircle2 className="h-5 w-5 text-green-400 shrink-0" />
                        ) : result.status === "fail" ? (
                          <XCircle className="h-5 w-5 text-red-400 shrink-0" />
                        ) : result.status === "warning" ? (
                          <AlertTriangle className="h-5 w-5 text-yellow-400 shrink-0" />
                        ) : (
                          <Minus className="h-5 w-5 text-slate-400 shrink-0" />
                        )}
                        <div className="flex-1 min-w-0">
                          <div className="font-medium text-sm truncate">{check.title}</div>
                          <div className="text-xs text-muted-foreground">{check.cisBenchmark} · {check.defaultResource}</div>
                        </div>
                        <Badge variant="outline" className={SEVERITY_COLORS[check.severity]}>
                          {check.severity}
                        </Badge>
                        {expanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                      </div>
                      {expanded && (
                        <div className="px-3 pb-3 pt-0 border-t border-border/50 space-y-2">
                          <p className="text-sm text-muted-foreground">{check.description}</p>
                          <div className="grid grid-cols-2 gap-2 text-xs">
                            <div><span className="text-muted-foreground">Current:</span> {result.currentValue}</div>
                            <div><span className="text-muted-foreground">Expected:</span> {result.expectedValue}</div>
                          </div>
                          {check.mitreTechniques.length > 0 && (
                            <div className="flex gap-1 flex-wrap">
                              {check.mitreTechniques.map((t: string) => (
                                <Badge key={t} variant="outline" className="text-xs">{t}</Badge>
                              ))}
                            </div>
                          )}
                          {result.status === "fail" && check.remediationSteps.length > 0 && (
                            <div className="bg-muted/30 rounded p-2">
                              <div className="text-xs font-medium mb-1">Remediation Steps:</div>
                              <ol className="text-xs text-muted-foreground list-decimal list-inside space-y-0.5">
                                {check.remediationSteps.map((step: string, i: number) => (
                                  <li key={i}>{step}</li>
                                ))}
                              </ol>
                            </div>
                          )}
                        </div>
                      )}
                    </Card>
                  );
                })}
              </div>
            </div>
          )}
        </TabsContent>

        {/* Check Catalog Tab */}
        <TabsContent value="checks" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">
                {PROVIDER_META[provider].label} CIS Benchmark Checks
              </CardTitle>
              <CardDescription>
                {checksData?.total || 0} checks across 5 domains
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex gap-2 mb-4">
                <Badge variant="outline" className={SEVERITY_COLORS.critical}>
                  {checksData?.bySeverity.critical || 0} Critical
                </Badge>
                <Badge variant="outline" className={SEVERITY_COLORS.high}>
                  {checksData?.bySeverity.high || 0} High
                </Badge>
                <Badge variant="outline" className={SEVERITY_COLORS.medium}>
                  {checksData?.bySeverity.medium || 0} Medium
                </Badge>
                <Badge variant="outline" className={SEVERITY_COLORS.low}>
                  {checksData?.bySeverity.low || 0} Low
                </Badge>
              </div>
              <div className="space-y-2">
                {checksData?.checks.map((check: any) => (
                  <div key={check.id} className="p-3 rounded-lg bg-muted/20 hover:bg-muted/30 transition-colors">
                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className={SEVERITY_COLORS[check.severity]}>
                        {check.severity}
                      </Badge>
                      <span className="font-medium text-sm">{check.title}</span>
                      <span className="text-xs text-muted-foreground ml-auto">{check.cisBenchmark}</span>
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">{check.description}</p>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* MITRE Coverage Tab */}
        <TabsContent value="coverage" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">MITRE ATT&CK Cloud Technique Coverage</CardTitle>
              <CardDescription>
                {mitreCoverage?.totalTechniques || 0} techniques covered by {mitreCoverage?.totalChecks || 0} checks
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {mitreCoverage?.techniques.map((tech: any) => (
                  <div key={tech.techniqueId} className="p-3 rounded-lg bg-muted/20 flex items-center gap-3">
                    <Badge variant="outline" className="font-mono text-xs">{tech.techniqueId}</Badge>
                    <div className="flex-1">
                      <div className="text-sm">{tech.checkCount} check{tech.checkCount !== 1 ? "s" : ""}</div>
                      <div className="flex gap-1 mt-1">
                        {tech.domains.map((d: string) => (
                          <Badge key={d} variant="secondary" className="text-xs">{d}</Badge>
                        ))}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
      </AppShell>
  );
}
