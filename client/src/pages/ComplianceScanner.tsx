"use client";
import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { Textarea } from "@/components/ui/textarea";
import {
  Loader2, Shield, ShieldCheck, ShieldAlert, ShieldX,
  CheckCircle2, XCircle, AlertTriangle, HelpCircle, MinusCircle,
  Upload, Play, FileText, BarChart3
} from "lucide-react";
import AppShell from "@/components/AppShell";

type ComplianceStatus = "pass" | "fail" | "not_applicable" | "error" | "manual_review";

const StatusIcon = ({ status }: { status: ComplianceStatus }) => {
  switch (status) {
    case "pass": return <CheckCircle2 className="w-4 h-4 text-green-500" />;
    case "fail": return <XCircle className="w-4 h-4 text-red-500" />;
    case "not_applicable": return <MinusCircle className="w-4 h-4 text-gray-400" />;
    case "error": return <AlertTriangle className="w-4 h-4 text-yellow-500" />;
    case "manual_review": return <HelpCircle className="w-4 h-4 text-blue-400" />;
  }
};

const StatusBadge = ({ status }: { status: ComplianceStatus }) => {
  const config: Record<ComplianceStatus, { color: string; label: string }> = {
    pass: { color: "bg-green-600 text-white", label: "PASS" },
    fail: { color: "bg-red-600 text-white", label: "FAIL" },
    not_applicable: { color: "bg-gray-500 text-white", label: "N/A" },
    error: { color: "bg-yellow-600 text-white", label: "ERROR" },
    manual_review: { color: "bg-blue-500 text-white", label: "REVIEW" },
  };
  const c = config[status];
  return <Badge className={c.color}>{c.label}</Badge>;
};

const SeverityBadge = ({ severity }: { severity: string }) => {
  const color: Record<string, string> = {
    critical: "bg-red-600 text-white",
    high: "bg-orange-500 text-white",
    medium: "bg-yellow-500 text-white",
    low: "bg-blue-500 text-white",
    info: "bg-gray-500 text-white",
  };
  return <Badge className={color[severity] || "bg-gray-400 text-white"}>{severity}</Badge>;
};

const ComplianceScanner = () => {
  const [target, setTarget] = useState("");
  const [scanResult, setScanResult] = useState<any>(null);
  const [importResult, setImportResult] = useState<any>(null);
  const [reportType, setReportType] = useState<"openscap_xccdf" | "lynis">("openscap_xccdf");
  const [reportContent, setReportContent] = useState("");
  const [importTarget, setImportTarget] = useState("");
  const [activeTab, setActiveTab] = useState("scan");
  const [filterStatus, setFilterStatus] = useState<string>("all");
  const [filterCategory, setFilterCategory] = useState<string>("all");

  const runScanMutation = trpc.vulnScanner.runComplianceScan.useMutation({
    onSuccess: (data) => {
      setScanResult(data);
      toast.success(`Compliance scan complete: ${data.complianceScore}% compliant (${data.passed}/${data.totalChecks - data.notApplicable - data.errors} checks passed)`);
    },
    onError: (err) => toast.error(`Scan failed: ${err.message}`),
  });

  const importMutation = trpc.vulnScanner.importComplianceReport.useMutation({
    onSuccess: (data) => {
      setImportResult(data);
      toast.success(`Report imported: ${data.complianceScore}% compliant (${data.totalChecks} checks)`);
    },
    onError: (err) => toast.error(`Import failed: ${err.message}`),
  });

  const handleRunScan = () => {
    if (!target) { toast.error("Target hostname is required"); return; }
    runScanMutation.mutate({ target });
  };

  const handleImport = () => {
    if (!importTarget || !reportContent) { toast.error("Target and report content are required"); return; }
    importMutation.mutate({ target: importTarget, reportType, reportContent });
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      setReportContent(ev.target?.result as string);
      toast.success(`Loaded ${file.name} (${(file.size / 1024).toFixed(1)} KB)`);
    };
    reader.readAsText(file);
  };

  const displayResult = scanResult || importResult;

  const filteredChecks = useMemo(() => {
    if (!displayResult?.checks) return [];
    return displayResult.checks.filter((c: any) => {
      if (filterStatus !== "all" && c.status !== filterStatus) return false;
      if (filterCategory !== "all" && c.category !== filterCategory) return false;
      return true;
    });
  }, [displayResult, filterStatus, filterCategory]);

  const categories = useMemo(() => {
    if (!displayResult?.checks) return [];
    return [...new Set(displayResult.checks.map((c: any) => c.category))];
  }, [displayResult]);

  return (
    <AppShell activePath="/compliance-scanner">
      <div className="space-y-6">
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="scan"><Play className="w-4 h-4 mr-1" /> External Audit</TabsTrigger>
          <TabsTrigger value="import"><Upload className="w-4 h-4 mr-1" /> Import Report</TabsTrigger>
          {displayResult && <TabsTrigger value="results"><BarChart3 className="w-4 h-4 mr-1" /> Results</TabsTrigger>}
        </TabsList>

        {/* External Compliance Scan */}
        <TabsContent value="scan" className="space-y-4">
          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <Shield className="w-5 h-5 text-primary" />
                <CardTitle>External Configuration Compliance Audit</CardTitle>
              </div>
              <CardDescription>
                Run CIS Benchmark, DISA STIG, and NIST 800-53 compliance checks against a target from the outside.
                Checks TLS configuration, HTTP security headers, DNS security, service hardening, and authentication controls.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="md:col-span-2 space-y-2">
                  <Label>Target Hostname</Label>
                  <Input
                    placeholder="example.com or api.example.com"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                  />
                </div>
                <div className="flex items-end">
                  <Button onClick={handleRunScan} disabled={runScanMutation.isPending} className="w-full">
                    {runScanMutation.isPending ? (
                      <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> Scanning...</>
                    ) : (
                      <><Play className="w-4 h-4 mr-2" /> Run Compliance Scan</>
                    )}
                  </Button>
                </div>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-5 gap-2 text-xs">
                {["TLS Config", "HTTP Headers", "DNS Security", "Service Hardening", "Authentication"].map((cat) => (
                  <div key={cat} className="flex items-center gap-1 text-muted-foreground">
                    <CheckCircle2 className="w-3 h-3 text-green-500" />
                    {cat}
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Import Compliance Report */}
        <TabsContent value="import" className="space-y-4">
          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <Upload className="w-5 h-5 text-primary" />
                <CardTitle>Import Authenticated Compliance Report</CardTitle>
              </div>
              <CardDescription>
                Upload OpenSCAP XCCDF results or Lynis audit reports from authenticated scans.
                This satisfies FedRAMP requirements for credentialed configuration compliance scanning.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Target System</Label>
                  <Input
                    placeholder="hostname or IP of scanned system"
                    value={importTarget}
                    onChange={(e) => setImportTarget(e.target.value)}
                  />
                </div>
                <div className="space-y-2">
                  <Label>Report Type</Label>
                  <Select value={reportType} onValueChange={(v) => setReportType(v as any)}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="openscap_xccdf">OpenSCAP XCCDF Results</SelectItem>
                      <SelectItem value="lynis">Lynis Security Audit</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div className="space-y-2">
                <Label>Report File</Label>
                <div className="flex gap-2">
                  <Input type="file" accept=".xml,.txt,.log,.json" onChange={handleFileUpload} />
                </div>
                {reportContent && (
                  <p className="text-xs text-muted-foreground">
                    <FileText className="w-3 h-3 inline mr-1" />
                    Loaded {(reportContent.length / 1024).toFixed(1)} KB of report data
                  </p>
                )}
              </div>

              <div className="space-y-2">
                <Label>Or paste report content</Label>
                <Textarea
                  placeholder="Paste OpenSCAP XCCDF XML or Lynis report output here..."
                  value={reportContent}
                  onChange={(e) => setReportContent(e.target.value)}
                  rows={6}
                  className="font-mono text-xs"
                />
              </div>

              <Button onClick={handleImport} disabled={importMutation.isPending}>
                {importMutation.isPending ? (
                  <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> Importing...</>
                ) : (
                  <><Upload className="w-4 h-4 mr-2" /> Import Report</>
                )}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Results */}
        {displayResult && (
          <TabsContent value="results" className="space-y-4">
            {/* Score Overview */}
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
              <Card>
                <CardContent className="pt-6 text-center">
                  <div className="text-3xl font-bold" style={{
                    color: displayResult.complianceScore >= 80 ? '#22c55e' :
                           displayResult.complianceScore >= 60 ? '#eab308' :
                           displayResult.complianceScore >= 40 ? '#f97316' : '#ef4444'
                  }}>
                    {displayResult.complianceScore}%
                  </div>
                  <p className="text-xs text-muted-foreground mt-1">Compliance Score</p>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="pt-6 text-center">
                  <div className="flex items-center justify-center gap-1">
                    <CheckCircle2 className="w-5 h-5 text-green-500" />
                    <span className="text-2xl font-bold">{displayResult.passed}</span>
                  </div>
                  <p className="text-xs text-muted-foreground mt-1">Passed</p>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="pt-6 text-center">
                  <div className="flex items-center justify-center gap-1">
                    <XCircle className="w-5 h-5 text-red-500" />
                    <span className="text-2xl font-bold">{displayResult.failed}</span>
                  </div>
                  <p className="text-xs text-muted-foreground mt-1">Failed</p>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="pt-6 text-center">
                  <div className="flex items-center justify-center gap-1">
                    <MinusCircle className="w-5 h-5 text-gray-400" />
                    <span className="text-2xl font-bold">{displayResult.notApplicable}</span>
                  </div>
                  <p className="text-xs text-muted-foreground mt-1">N/A</p>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="pt-6 text-center">
                  <div className="flex items-center justify-center gap-1">
                    <HelpCircle className="w-5 h-5 text-blue-400" />
                    <span className="text-2xl font-bold">{displayResult.manualReview + displayResult.errors}</span>
                  </div>
                  <p className="text-xs text-muted-foreground mt-1">Review / Error</p>
                </CardContent>
              </Card>
            </div>

            {/* Compliance Progress Bar */}
            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium">Overall Compliance</span>
                  <span className="text-sm text-muted-foreground">{displayResult.benchmarkProfile}</span>
                </div>
                <Progress value={displayResult.complianceScore} className="h-3" />
                <p className="text-xs text-muted-foreground mt-2">
                  {displayResult.scanType === "external" ? "External" : "Authenticated"} scan of {displayResult.target} completed in {(displayResult.durationMs / 1000).toFixed(1)}s
                </p>
              </CardContent>
            </Card>

            {/* Category Breakdown */}
            <Card>
              <CardHeader>
                <CardTitle className="text-sm">Compliance by Category</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {categories.map((cat: string) => {
                    const catChecks = displayResult.checks.filter((c: any) => c.category === cat);
                    const catPassed = catChecks.filter((c: any) => c.status === "pass").length;
                    const catApplicable = catChecks.filter((c: any) => c.status !== "not_applicable" && c.status !== "error").length;
                    const catScore = catApplicable > 0 ? Math.round((catPassed / catApplicable) * 100) : 0;
                    return (
                      <div key={cat} className="flex items-center gap-3">
                        <span className="text-xs w-40 truncate capitalize">{cat.replace(/_/g, " ")}</span>
                        <Progress value={catScore} className="h-2 flex-1" />
                        <span className="text-xs text-muted-foreground w-16 text-right">{catPassed}/{catApplicable}</span>
                      </div>
                    );
                  })}
                </div>
              </CardContent>
            </Card>

            {/* Detailed Checks Table */}
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm">Detailed Check Results</CardTitle>
                  <div className="flex gap-2">
                    <Select value={filterStatus} onValueChange={setFilterStatus}>
                      <SelectTrigger className="w-32 h-8 text-xs"><SelectValue placeholder="Status" /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All Status</SelectItem>
                        <SelectItem value="pass">Pass</SelectItem>
                        <SelectItem value="fail">Fail</SelectItem>
                        <SelectItem value="not_applicable">N/A</SelectItem>
                        <SelectItem value="error">Error</SelectItem>
                        <SelectItem value="manual_review">Review</SelectItem>
                      </SelectContent>
                    </Select>
                    <Select value={filterCategory} onValueChange={setFilterCategory}>
                      <SelectTrigger className="w-40 h-8 text-xs"><SelectValue placeholder="Category" /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All Categories</SelectItem>
                        {categories.map((cat: string) => (
                          <SelectItem key={cat} value={cat}>{cat.replace(/_/g, " ")}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-10"></TableHead>
                      <TableHead>Check</TableHead>
                      <TableHead>Benchmark</TableHead>
                      <TableHead>Severity</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>NIST Controls</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredChecks.map((check: any) => (
                      <TableRow key={check.checkId}>
                        <TableCell><StatusIcon status={check.status} /></TableCell>
                        <TableCell>
                          <div>
                            <p className="font-medium text-sm">{check.title}</p>
                            <p className="text-xs text-muted-foreground mt-0.5 line-clamp-2">{check.evidence}</p>
                            {check.status === "fail" && (
                              <p className="text-xs text-orange-400 mt-1"><AlertTriangle className="w-3 h-3 inline mr-1" />{check.remediation}</p>
                            )}
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="text-xs">
                            <p className="font-mono">{check.benchmarkRef}</p>
                            {check.stigId && <p className="text-muted-foreground">{check.stigId}</p>}
                          </div>
                        </TableCell>
                        <TableCell><SeverityBadge severity={check.severity} /></TableCell>
                        <TableCell><StatusBadge status={check.status} /></TableCell>
                        <TableCell>
                          <div className="flex flex-wrap gap-1">
                            {check.nistControls?.slice(0, 3).map((ctrl: string) => (
                              <Badge key={ctrl} variant="outline" className="text-[10px] px-1">{ctrl}</Badge>
                            ))}
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </TabsContent>
        )}
      </Tabs>

      {/* FedRAMP Note */}
      <Card className="border-blue-500/30 bg-blue-500/5">
        <CardContent className="pt-6">
          <div className="flex items-start gap-3">
            <ShieldCheck className="w-5 h-5 text-blue-500 mt-0.5 shrink-0" />
            <div>
              <p className="font-semibold text-sm">SCAP/STIG Compliance — FedRAMP CM-6, SI-2, RA-5</p>
              <p className="text-xs text-muted-foreground mt-1">
                Configuration compliance scanning satisfies FedRAMP CM-6 (Configuration Settings), SI-2 (Flaw Remediation),
                and RA-5 (Vulnerability Monitoring) controls. External audits check TLS, headers, DNS, and service hardening
                against CIS Benchmarks and DISA STIGs. For full compliance, import authenticated OpenSCAP or Lynis reports
                from credentialed scans of your systems.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
    </AppShell>
  );
};

export default ComplianceScanner;
