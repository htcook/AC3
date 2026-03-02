import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { toast } from "sonner";
import {
  ShieldCheck, Play, FileText, Download, CheckCircle2, XCircle,
  AlertTriangle, Loader2, Lock, Hash, Clock, ChevronDown, ChevronRight,
  FileSpreadsheet, Shield, Fingerprint, Eye, BarChart3
} from "lucide-react";
import AppShell from "@/components/AppShell";

type TestCategory = "technique_validation" | "configuration_audit" | "bypass_resistance" | "coverage_gap" | "degradation_test";

const CATEGORY_LABELS: Record<TestCategory, string> = {
  technique_validation: "Technique Validation",
  configuration_audit: "Configuration Audit",
  bypass_resistance: "Bypass Resistance",
  coverage_gap: "Coverage Gap",
  degradation_test: "Degradation Test",
};

const CATEGORY_ICONS: Record<TestCategory, typeof Shield> = {
  technique_validation: Fingerprint,
  configuration_audit: Eye,
  bypass_resistance: Shield,
  coverage_gap: AlertTriangle,
  degradation_test: BarChart3,
};

export default function ControlTesting() {
  const [selectedCategory, setSelectedCategory] = useState("");
  const [controlName, setControlName] = useState("");
  const [environment, setEnvironment] = useState("");
  const [excludeManual, setExcludeManual] = useState(false);
  const [maxRiskLevel, setMaxRiskLevel] = useState<"low" | "medium" | "high">("high");
  const [activeTab, setActiveTab] = useState("setup");
  const [validationReport, setValidationReport] = useState<any>(null);
  const [expandedTests, setExpandedTests] = useState<Set<string>>(new Set());
  const [expandedEvidence, setExpandedEvidence] = useState<Set<string>>(new Set());

  // Config fields for the selected control
  const [blockingMode, setBlockingMode] = useState(true);
  const [loggingEnabled, setLoggingEnabled] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(() => new Date().toISOString().split("T")[0]);
  const [coveragePercent, setCoveragePercent] = useState(85);

  const categoriesQuery = trpc.compensatingControls.getSupportedTestCategories.useQuery();

  const runSuiteMut = trpc.compensatingControls.runFullTestSuite.useMutation({
    onSuccess: (data) => {
      setValidationReport(data);
      setActiveTab("results");
      toast.success("Validation complete — evidence package generated");
    },
    onError: (err) => toast.error(err.message),
  });

  const exportMarkdownMut = trpc.compensatingControls.exportReportMarkdown.useMutation({
    onSuccess: (data) => {
      const blob = new Blob([data.markdown], { type: "text/markdown" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `control-validation-${validationReport?.reportId || "report"}.md`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success("Markdown report downloaded");
    },
    onError: (err) => toast.error(err.message),
  });

  const exportCSVMut = trpc.compensatingControls.exportEvidenceCSV.useMutation({
    onSuccess: (data) => {
      const blob = new Blob([data.csv], { type: "text/csv" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `evidence-chain-${validationReport?.reportId || "report"}.csv`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success("Evidence CSV downloaded");
    },
    onError: (err) => toast.error(err.message),
  });

  const verifyChainMut = trpc.compensatingControls.verifyEvidenceChain.useMutation({
    onSuccess: (data) => {
      if (data.valid) {
        toast.success(`Evidence chain verified — ${data.verifiedRecords} records intact`);
      } else {
        toast.error(`Evidence chain BROKEN at record ${data.brokenAt}: ${data.details}`);
      }
    },
    onError: (err) => toast.error(err.message),
  });

  const handleRunSuite = () => {
    if (!selectedCategory) { toast.error("Select a control category"); return; }
    if (!controlName.trim()) { toast.error("Enter a control name"); return; }
    if (!environment.trim()) { toast.error("Enter the target environment"); return; }

    runSuiteMut.mutate({
      controlCategory: selectedCategory,
      controlName: controlName.trim(),
      environment: environment.trim(),
      excludeManual,
      maxRiskLevel,
      controlConfig: {
        blockingMode,
        loggingEnabled,
        lastUpdated: new Date(lastUpdated).toISOString(),
        coveragePercent,
      },
    });
  };

  const handleExportMarkdown = () => {
    if (!validationReport) return;
    exportMarkdownMut.mutate({ reportData: validationReport });
  };

  const handleExportCSV = () => {
    if (!validationReport) return;
    exportCSVMut.mutate({ reportData: validationReport });
  };

  const handleVerifyChain = () => {
    if (!validationReport) return;
    const allEvidence = validationReport.testResults.flatMap((tr: any) => tr.evidenceRecords);
    verifyChainMut.mutate({ evidenceRecords: allEvidence });
  };

  const toggleTest = (testId: string) => {
    setExpandedTests(prev => {
      const next = new Set(prev);
      next.has(testId) ? next.delete(testId) : next.add(testId);
      return next;
    });
  };

  const toggleEvidence = (evidenceId: string) => {
    setExpandedEvidence(prev => {
      const next = new Set(prev);
      next.has(evidenceId) ? next.delete(evidenceId) : next.add(evidenceId);
      return next;
    });
  };

  const verdictColor = (verdict: string) => {
    switch (verdict) {
      case "effective": return "text-green-500 bg-green-500/10";
      case "partially_effective": return "text-yellow-500 bg-yellow-500/10";
      case "ineffective": return "text-red-500 bg-red-500/10";
      default: return "text-muted-foreground bg-muted";
    }
  };

  const severityColor = (severity: string) => {
    switch (severity) {
      case "critical": return "bg-red-600 text-white";
      case "high": return "bg-red-500 text-white";
      case "medium": return "bg-yellow-500 text-black";
      case "low": return "bg-blue-500 text-white";
      case "info": return "bg-slate-500 text-white";
      default: return "bg-muted";
    }
  };

  const selectedCategoryData = useMemo(() => {
    return categoriesQuery.data?.find((c: any) => c.category === selectedCategory);
  }, [categoriesQuery.data, selectedCategory]);

  const totalEvidence = useMemo(() => {
    if (!validationReport) return 0;
    return validationReport.testResults.reduce((sum: number, tr: any) => sum + (tr.evidenceRecords?.length || 0), 0);
  }, [validationReport]);

  return (
    <AppShell activePath="/control-testing">
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <ShieldCheck className="h-6 w-6 text-emerald-500" />
            Compensating Control Testing
          </h1>
          <p className="text-muted-foreground mt-1 max-w-3xl">
            Validate compensating controls against the specific threats they mitigate. Produces audit-grade evidence packages with SHA-256 integrity hashing, timestamped execution logs, and exportable reports for risk officials and auditors.
          </p>
        </div>

        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList>
            <TabsTrigger value="setup">Test Setup</TabsTrigger>
            <TabsTrigger value="results" disabled={!validationReport}>
              Results {validationReport && <Badge variant="outline" className="ml-1 text-xs">{validationReport.overallScore}/100</Badge>}
            </TabsTrigger>
            <TabsTrigger value="evidence" disabled={!validationReport}>
              Evidence Chain {validationReport && <Badge variant="outline" className="ml-1 text-xs">{totalEvidence}</Badge>}
            </TabsTrigger>
            <TabsTrigger value="compliance" disabled={!validationReport}>Compliance</TabsTrigger>
            <TabsTrigger value="export" disabled={!validationReport}>Export</TabsTrigger>
          </TabsList>

          {/* ─── SETUP TAB ─── */}
          <TabsContent value="setup" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle>Select Control to Test</CardTitle>
                <CardDescription>Choose the compensating control category and configure test parameters</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Control Category</label>
                    <Select value={selectedCategory} onValueChange={setSelectedCategory}>
                      <SelectTrigger>
                        <SelectValue placeholder="Select control type..." />
                      </SelectTrigger>
                      <SelectContent>
                        {categoriesQuery.data?.map((cat: any) => (
                          <SelectItem key={cat.category} value={cat.category}>
                            {cat.category.replace(/_/g, " ").toUpperCase()} ({cat.testCount} tests)
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Control Name / Instance</label>
                    <Input
                      placeholder="e.g., Cloudflare WAF, CrowdStrike Falcon, Duo MFA"
                      value={controlName}
                      onChange={e => setControlName(e.target.value)}
                    />
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Target Environment</label>
                    <Input
                      placeholder="e.g., Production Web Tier, Staging API"
                      value={environment}
                      onChange={e => setEnvironment(e.target.value)}
                    />
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Max Test Risk Level</label>
                    <Select value={maxRiskLevel} onValueChange={(v: any) => setMaxRiskLevel(v)}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="low">Low Risk Only</SelectItem>
                        <SelectItem value="medium">Up to Medium Risk</SelectItem>
                        <SelectItem value="high">All (Including High Risk)</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="flex items-end gap-2 pb-1">
                    <Switch checked={excludeManual} onCheckedChange={setExcludeManual} />
                    <label className="text-sm">Exclude manual tests</label>
                  </div>
                </div>

                {selectedCategoryData && (
                  <div className="p-3 rounded-lg bg-muted/50 border">
                    <div className="flex items-center gap-4 text-sm">
                      <span><strong>{selectedCategoryData.testCount}</strong> tests available</span>
                      <Separator orientation="vertical" className="h-4" />
                      <span>ATT&CK: {selectedCategoryData.mitreTechniques.join(", ")}</span>
                      <Separator orientation="vertical" className="h-4" />
                      <span>NIST: {selectedCategoryData.nistControls.join(", ")}</span>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Control Configuration */}
            <Card>
              <CardHeader>
                <CardTitle>Control Configuration</CardTitle>
                <CardDescription>Provide current control settings for accurate assessment. These details directly affect the validation score.</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                  <div className="flex items-center justify-between p-3 rounded-lg border">
                    <div>
                      <div className="text-sm font-medium">Blocking Mode</div>
                      <div className="text-xs text-muted-foreground">Active prevention vs. detect-only</div>
                    </div>
                    <Switch checked={blockingMode} onCheckedChange={setBlockingMode} />
                  </div>
                  <div className="flex items-center justify-between p-3 rounded-lg border">
                    <div>
                      <div className="text-sm font-medium">Logging Enabled</div>
                      <div className="text-xs text-muted-foreground">Audit trail for all events</div>
                    </div>
                    <Switch checked={loggingEnabled} onCheckedChange={setLoggingEnabled} />
                  </div>
                  <div className="space-y-1 p-3 rounded-lg border">
                    <div className="text-sm font-medium">Last Updated</div>
                    <Input type="date" value={lastUpdated} onChange={e => setLastUpdated(e.target.value)} className="h-8" />
                  </div>
                  <div className="space-y-1 p-3 rounded-lg border">
                    <div className="text-sm font-medium">Coverage %</div>
                    <div className="flex items-center gap-2">
                      <Input
                        type="number"
                        min={0}
                        max={100}
                        value={coveragePercent}
                        onChange={e => setCoveragePercent(Number(e.target.value))}
                        className="h-8 w-20"
                      />
                      <Progress value={coveragePercent} className="flex-1 h-2" />
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Button
              size="lg"
              onClick={handleRunSuite}
              disabled={runSuiteMut.isPending || !selectedCategory || !controlName.trim()}
              className="w-full"
            >
              {runSuiteMut.isPending ? (
                <><Loader2 className="h-4 w-4 animate-spin mr-2" /> Running Validation Suite...</>
              ) : (
                <><Play className="h-4 w-4 mr-2" /> Run Validation Suite</>
              )}
            </Button>
          </TabsContent>

          {/* ─── RESULTS TAB ─── */}
          <TabsContent value="results" className="space-y-4">
            {validationReport && (
              <>
                {/* Executive Summary */}
                <Card>
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <div>
                        <CardTitle>Validation Report — {validationReport.controlName}</CardTitle>
                        <CardDescription>Report ID: {validationReport.reportId} | Generated: {new Date(validationReport.generatedAt).toLocaleString()}</CardDescription>
                      </div>
                      <div className={`px-4 py-2 rounded-lg text-center ${verdictColor(validationReport.overallVerdict)}`}>
                        <div className="text-2xl font-bold">{validationReport.overallScore}/100</div>
                        <div className="text-xs font-medium uppercase">{validationReport.overallVerdict?.replace(/_/g, " ")}</div>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                      <div className="text-center p-3 rounded-lg bg-muted">
                        <div className="text-xl font-bold">{validationReport.testResults?.length || 0}</div>
                        <div className="text-xs text-muted-foreground">Tests Run</div>
                      </div>
                      <div className="text-center p-3 rounded-lg bg-muted">
                        <div className="text-xl font-bold text-green-500">
                          {validationReport.testResults?.filter((tr: any) => tr.execution?.status === "passed").length || 0}
                        </div>
                        <div className="text-xs text-muted-foreground">Passed</div>
                      </div>
                      <div className="text-center p-3 rounded-lg bg-muted">
                        <div className="text-xl font-bold text-red-500">
                          {validationReport.testResults?.filter((tr: any) => tr.execution?.status === "failed").length || 0}
                        </div>
                        <div className="text-xs text-muted-foreground">Failed</div>
                      </div>
                      <div className="text-center p-3 rounded-lg bg-muted">
                        <div className="text-xl font-bold">{totalEvidence}</div>
                        <div className="text-xs text-muted-foreground">Evidence Records</div>
                      </div>
                      <div className="text-center p-3 rounded-lg bg-muted">
                        <div className="flex items-center justify-center gap-1">
                          {validationReport.signatureBlock?.evidenceChainValid ? (
                            <Lock className="h-4 w-4 text-green-500" />
                          ) : (
                            <AlertTriangle className="h-4 w-4 text-red-500" />
                          )}
                          <span className="text-xl font-bold">
                            {validationReport.signatureBlock?.evidenceChainValid ? "Valid" : "Broken"}
                          </span>
                        </div>
                        <div className="text-xs text-muted-foreground">Chain Integrity</div>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                {/* Risk Assessment */}
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">Risk Assessment</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                      <div className="p-3 rounded-lg border">
                        <div className="text-xs text-muted-foreground">Residual Risk</div>
                        <Badge className={
                          validationReport.riskAssessment?.residualRisk === "low" ? "bg-green-500" :
                          validationReport.riskAssessment?.residualRisk === "medium" ? "bg-yellow-500 text-black" :
                          validationReport.riskAssessment?.residualRisk === "high" ? "bg-red-500" : "bg-red-700"
                        }>
                          {validationReport.riskAssessment?.residualRisk?.toUpperCase()}
                        </Badge>
                      </div>
                      <div className="p-3 rounded-lg border">
                        <div className="text-xs text-muted-foreground">Mitigation Effectiveness</div>
                        <div className="text-lg font-bold">{validationReport.riskAssessment?.mitigationEffectiveness}%</div>
                      </div>
                      <div className="p-3 rounded-lg border">
                        <div className="text-xs text-muted-foreground">Validation Expires</div>
                        <div className="text-sm font-medium">{validationReport.riskAssessment?.expirationDate?.split("T")[0]}</div>
                      </div>
                      <div className="p-3 rounded-lg border">
                        <div className="text-xs text-muted-foreground">Review Frequency</div>
                        <div className="text-sm font-medium capitalize">{validationReport.riskAssessment?.reviewFrequency}</div>
                      </div>
                    </div>
                    {validationReport.riskAssessment?.conditions?.length > 0 && (
                      <div className="mt-3 p-3 rounded-lg bg-muted/50">
                        <div className="text-xs font-medium mb-1">Conditions for Continued Acceptance:</div>
                        {validationReport.riskAssessment.conditions.map((c: string, i: number) => (
                          <div key={i} className="text-xs text-muted-foreground flex items-start gap-1 mt-0.5">
                            <span className="text-muted-foreground/50">•</span> {c}
                          </div>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>

                {/* Individual Test Results */}
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">Test Results</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    {validationReport.testResults?.map((tr: any, i: number) => {
                      const isExpanded = expandedTests.has(tr.testCase.testId);
                      const CatIcon = CATEGORY_ICONS[tr.testCase.testCategory as TestCategory] || Shield;
                      return (
                        <div key={tr.testCase.testId} className="border rounded-lg">
                          <button
                            onClick={() => toggleTest(tr.testCase.testId)}
                            className="w-full flex items-center justify-between p-3 hover:bg-muted/50 transition-colors"
                          >
                            <div className="flex items-center gap-3">
                              {tr.execution?.status === "passed" ? (
                                <CheckCircle2 className="h-5 w-5 text-green-500 shrink-0" />
                              ) : (
                                <XCircle className="h-5 w-5 text-red-500 shrink-0" />
                              )}
                              <CatIcon className="h-4 w-4 text-muted-foreground shrink-0" />
                              <div className="text-left">
                                <div className="text-sm font-medium">{tr.testCase.title}</div>
                                <div className="text-xs text-muted-foreground">
                                  {CATEGORY_LABELS[tr.testCase.testCategory as TestCategory]} | {tr.testCase.mitreTechniques.join(", ")}
                                </div>
                              </div>
                            </div>
                            <div className="flex items-center gap-2">
                              <Badge variant="outline" className={tr.execution?.result?.score >= 80 ? "text-green-500" : tr.execution?.result?.score >= 60 ? "text-yellow-500" : "text-red-500"}>
                                {tr.execution?.result?.score}/100
                              </Badge>
                              <Badge variant="outline" className="text-xs">
                                {tr.evidenceRecords?.length || 0} evidence
                              </Badge>
                              {isExpanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                            </div>
                          </button>
                          {isExpanded && tr.execution?.result && (
                            <div className="px-3 pb-3 space-y-3 border-t">
                              <div className="pt-3">
                                <div className="text-sm">{tr.execution.result.summary}</div>
                              </div>
                              {/* Findings */}
                              {tr.execution.result.detailedFindings?.length > 0 && (
                                <div>
                                  <div className="text-xs font-medium mb-1">Findings:</div>
                                  {tr.execution.result.detailedFindings.map((f: any) => (
                                    <div key={f.findingId} className="p-2 rounded border mb-1">
                                      <div className="flex items-center gap-2 mb-1">
                                        <Badge className={`text-xs ${severityColor(f.severity)}`}>{f.severity.toUpperCase()}</Badge>
                                        <span className="text-sm font-medium">{f.title}</span>
                                      </div>
                                      <div className="grid grid-cols-2 gap-2 text-xs">
                                        <div><span className="text-muted-foreground">Observed:</span> {f.observed}</div>
                                        <div><span className="text-muted-foreground">Expected:</span> {f.expected}</div>
                                      </div>
                                      <div className="text-xs mt-1"><span className="text-muted-foreground">Remediation:</span> {f.remediation}</div>
                                    </div>
                                  ))}
                                </div>
                              )}
                              {/* Recommendations */}
                              {tr.execution.result.recommendations?.length > 0 && (
                                <div className="p-2 rounded bg-muted/50">
                                  <div className="text-xs font-medium mb-1">Recommendations:</div>
                                  {tr.execution.result.recommendations.map((r: string, ri: number) => (
                                    <div key={ri} className="text-xs text-muted-foreground">• {r}</div>
                                  ))}
                                </div>
                              )}
                              {/* Test Procedure */}
                              <div className="p-2 rounded bg-muted/30">
                                <div className="text-xs font-medium mb-1">Test Procedure:</div>
                                <pre className="text-xs text-muted-foreground whitespace-pre-wrap">{tr.testCase.procedure}</pre>
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </CardContent>
                </Card>
              </>
            )}
          </TabsContent>

          {/* ─── EVIDENCE CHAIN TAB ─── */}
          <TabsContent value="evidence" className="space-y-4">
            {validationReport && (
              <>
                <Card>
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <div>
                        <CardTitle className="flex items-center gap-2">
                          <Hash className="h-5 w-5" />
                          Evidence Chain
                        </CardTitle>
                        <CardDescription>
                          {totalEvidence} records with SHA-256 integrity hashing and chain-of-custody tracking
                        </CardDescription>
                      </div>
                      <Button variant="outline" size="sm" onClick={handleVerifyChain} disabled={verifyChainMut.isPending}>
                        {verifyChainMut.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : <Lock className="h-4 w-4 mr-1" />}
                        Verify Chain Integrity
                      </Button>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="flex items-center gap-4 p-3 rounded-lg bg-muted mb-4">
                      <div className="flex items-center gap-1">
                        {validationReport.signatureBlock?.evidenceChainValid ? (
                          <CheckCircle2 className="h-4 w-4 text-green-500" />
                        ) : (
                          <XCircle className="h-4 w-4 text-red-500" />
                        )}
                        <span className="text-sm font-medium">
                          Chain: {validationReport.signatureBlock?.evidenceChainValid ? "VALID" : "BROKEN"}
                        </span>
                      </div>
                      <Separator orientation="vertical" className="h-4" />
                      <span className="text-sm text-muted-foreground">
                        Report Hash: <code className="text-xs">{validationReport.signatureBlock?.reportHash?.slice(0, 24)}...</code>
                      </span>
                    </div>

                    <ScrollArea className="h-[500px]">
                      <div className="space-y-1">
                        {validationReport.testResults?.flatMap((tr: any, ti: number) =>
                          (tr.evidenceRecords || []).map((ev: any, ei: number) => {
                            const isExpanded = expandedEvidence.has(ev.evidenceId);
                            return (
                              <div key={ev.evidenceId} className="border rounded">
                                <button
                                  onClick={() => toggleEvidence(ev.evidenceId)}
                                  className="w-full flex items-center justify-between p-2 hover:bg-muted/50 text-left"
                                >
                                  <div className="flex items-center gap-2">
                                    <div className="w-6 h-6 rounded-full bg-muted flex items-center justify-center text-xs font-mono">
                                      {ti * 4 + ei + 1}
                                    </div>
                                    <div>
                                      <div className="text-xs font-medium">{ev.title}</div>
                                      <div className="text-xs text-muted-foreground flex items-center gap-2">
                                        <Clock className="h-3 w-3" />
                                        {new Date(ev.timestamp).toLocaleString()}
                                        <Badge variant="outline" className="text-xs py-0">{ev.type.replace(/_/g, " ")}</Badge>
                                        <Badge variant="outline" className="text-xs py-0">{ev.classification}</Badge>
                                      </div>
                                    </div>
                                  </div>
                                  <div className="flex items-center gap-1">
                                    <code className="text-xs text-muted-foreground">{ev.contentHash?.slice(0, 12)}...</code>
                                    {isExpanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
                                  </div>
                                </button>
                                {isExpanded && (
                                  <div className="px-2 pb-2 border-t space-y-2">
                                    <div className="grid grid-cols-2 gap-2 pt-2 text-xs">
                                      <div>
                                        <span className="text-muted-foreground">Evidence ID:</span>
                                        <code className="ml-1">{ev.evidenceId}</code>
                                      </div>
                                      <div>
                                        <span className="text-muted-foreground">Execution ID:</span>
                                        <code className="ml-1">{ev.executionId}</code>
                                      </div>
                                      <div>
                                        <span className="text-muted-foreground">Content Hash:</span>
                                        <code className="ml-1 break-all">{ev.contentHash}</code>
                                      </div>
                                      <div>
                                        <span className="text-muted-foreground">Chain Hash:</span>
                                        <code className="ml-1 break-all">{ev.chainHash}</code>
                                      </div>
                                      <div>
                                        <span className="text-muted-foreground">Previous Hash:</span>
                                        <code className="ml-1 break-all">{ev.previousHash || "null (chain start)"}</code>
                                      </div>
                                      <div>
                                        <span className="text-muted-foreground">Collector:</span> {ev.collector}
                                      </div>
                                      <div>
                                        <span className="text-muted-foreground">Retention:</span> {ev.retentionDays} days
                                      </div>
                                    </div>
                                    <details className="text-xs">
                                      <summary className="cursor-pointer text-muted-foreground hover:text-foreground">View Raw Content</summary>
                                      <pre className="mt-1 p-2 rounded bg-muted overflow-x-auto text-xs max-h-48">{ev.content}</pre>
                                    </details>
                                  </div>
                                )}
                              </div>
                            );
                          })
                        )}
                      </div>
                    </ScrollArea>
                  </CardContent>
                </Card>
              </>
            )}
          </TabsContent>

          {/* ─── COMPLIANCE TAB ─── */}
          <TabsContent value="compliance" className="space-y-4">
            {validationReport && (
              <Card>
                <CardHeader>
                  <CardTitle>NIST SP 800-53 Compliance Mapping</CardTitle>
                  <CardDescription>How this control's test results map to federal security requirements</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {validationReport.complianceMapping?.map((cm: any, i: number) => (
                      <div key={i} className="flex items-center justify-between p-3 rounded-lg border">
                        <div className="flex items-center gap-3">
                          <Badge variant="outline" className="font-mono">{cm.controlId}</Badge>
                          <div>
                            <div className="text-sm font-medium">{cm.requirement}</div>
                            <div className="text-xs text-muted-foreground">{cm.framework}</div>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs text-muted-foreground">{cm.evidence}</span>
                          <Badge className={
                            cm.status === "satisfied" ? "bg-green-500" :
                            cm.status === "partially_satisfied" ? "bg-yellow-500 text-black" :
                            "bg-red-500"
                          }>
                            {cm.status?.replace(/_/g, " ").toUpperCase()}
                          </Badge>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}
          </TabsContent>

          {/* ─── EXPORT TAB ─── */}
          <TabsContent value="export" className="space-y-4">
            {validationReport && (
              <>
                <Card>
                  <CardHeader>
                    <CardTitle>Export Validation Evidence</CardTitle>
                    <CardDescription>
                      Download audit-grade evidence packages for risk officials and compliance auditors.
                      All exports include SHA-256 integrity hashes for tamper detection.
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <Card className="border-2 hover:border-primary/50 transition-colors cursor-pointer" onClick={handleExportMarkdown}>
                        <CardContent className="pt-6 text-center space-y-2">
                          <FileText className="h-10 w-10 mx-auto text-blue-500" />
                          <div className="font-medium">Validation Report (Markdown)</div>
                          <div className="text-xs text-muted-foreground">
                            Full report with executive summary, test results, findings, compliance mapping, and risk assessment.
                            Suitable for auditor review and management presentation.
                          </div>
                          <Button variant="outline" size="sm" disabled={exportMarkdownMut.isPending}>
                            {exportMarkdownMut.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : <Download className="h-4 w-4 mr-1" />}
                            Download .md
                          </Button>
                        </CardContent>
                      </Card>

                      <Card className="border-2 hover:border-primary/50 transition-colors cursor-pointer" onClick={handleExportCSV}>
                        <CardContent className="pt-6 text-center space-y-2">
                          <FileSpreadsheet className="h-10 w-10 mx-auto text-green-500" />
                          <div className="font-medium">Evidence Chain (CSV)</div>
                          <div className="text-xs text-muted-foreground">
                            Complete evidence record inventory with timestamps, hashes, classifications, and chain linkage.
                            Import into GRC tools or spreadsheets for audit tracking.
                          </div>
                          <Button variant="outline" size="sm" disabled={exportCSVMut.isPending}>
                            {exportCSVMut.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : <Download className="h-4 w-4 mr-1" />}
                            Download .csv
                          </Button>
                        </CardContent>
                      </Card>

                      <Card className="border-2 hover:border-primary/50 transition-colors cursor-pointer" onClick={() => {
                        const blob = new Blob([JSON.stringify(validationReport, null, 2)], { type: "application/json" });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement("a");
                        a.href = url;
                        a.download = `validation-report-${validationReport.reportId}.json`;
                        a.click();
                        URL.revokeObjectURL(url);
                        toast.success("JSON report downloaded");
                      }}>
                        <CardContent className="pt-6 text-center space-y-2">
                          <Hash className="h-10 w-10 mx-auto text-purple-500" />
                          <div className="font-medium">Raw Evidence (JSON)</div>
                          <div className="text-xs text-muted-foreground">
                            Complete validation data including all evidence records, hashes, and chain metadata.
                            Machine-readable format for automated compliance verification.
                          </div>
                          <Button variant="outline" size="sm">
                            <Download className="h-4 w-4 mr-1" />
                            Download .json
                          </Button>
                        </CardContent>
                      </Card>
                    </div>
                  </CardContent>
                </Card>

                {/* Integrity Verification */}
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base flex items-center gap-2">
                      <Lock className="h-4 w-4" />
                      Report Integrity
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-2 gap-4 text-sm">
                      <div>
                        <span className="text-muted-foreground">Report Hash:</span>
                        <code className="ml-2 text-xs break-all">{validationReport.signatureBlock?.reportHash}</code>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Evidence Chain:</span>
                        <span className={`ml-2 font-medium ${validationReport.signatureBlock?.evidenceChainValid ? "text-green-500" : "text-red-500"}`}>
                          {validationReport.signatureBlock?.evidenceChainValid ? "VALID" : "INTEGRITY VIOLATION"}
                        </span>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Total Evidence Records:</span>
                        <span className="ml-2 font-medium">{validationReport.signatureBlock?.totalEvidenceRecords}</span>
                      </div>
                      <div className="col-span-2 text-xs text-muted-foreground italic">
                        {validationReport.signatureBlock?.integrityStatement}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </>
            )}
          </TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
}
