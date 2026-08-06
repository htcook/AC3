import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Checkbox } from "@/components/ui/checkbox";
import { toast } from "sonner";
import {
  Shield, FileText, CheckCircle2, XCircle, AlertTriangle,
  BarChart3, ChevronDown, ChevronUp, Loader2, Download,
} from "lucide-react";

type ScanSource = "engagement" | "di_scan";

interface Props {
  scanSource: ScanSource;
  /** Engagement ID (for engagement scans) */
  engagementId?: number;
  /** Domain ID (for DI scans) */
  domainId?: number;
  /** Optional class name */
  className?: string;
}

const FRAMEWORK_INFO: Record<string, { label: string; color: string; icon: string; description: string }> = {
  nist_800_53: { label: "NIST 800-53 Rev 5", color: "text-purple-400 border-purple-500/30 bg-purple-500/10", icon: "🏛️", description: "Federal information security controls" },
  cis_v8: { label: "CIS Controls v8", color: "text-blue-400 border-blue-500/30 bg-blue-500/10", icon: "🛡️", description: "Critical security controls for cyber defense" },
  pci_dss_v4: { label: "PCI DSS v4.0", color: "text-orange-400 border-orange-500/30 bg-orange-500/10", icon: "💳", description: "Payment card industry data security standard" },
  iso_27001: { label: "ISO 27001:2022", color: "text-green-400 border-green-500/30 bg-green-500/10", icon: "🌐", description: "International information security management" },
  hipaa: { label: "HIPAA Security", color: "text-red-400 border-red-500/30 bg-red-500/10", icon: "🏥", description: "Health information privacy and security" },
  soc2: { label: "SOC 2 Type II", color: "text-cyan-400 border-cyan-500/30 bg-cyan-500/10", icon: "📋", description: "Service organization trust criteria" },
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400",
  high: "bg-orange-500/20 text-orange-400",
  medium: "bg-yellow-500/20 text-yellow-400",
  low: "bg-blue-500/20 text-blue-400",
  info: "bg-slate-500/20 text-slate-400",
};

interface ComplianceReportData {
  frameworks: Array<{
    frameworkId: string;
    frameworkName: string;
    totalControlsMapped: number;
    controlsByStatus: Record<string, number>;
    controls: Array<{
      controlId: string;
      controlTitle: string;
      status: string;
      findings: Array<{
        id: string;
        title: string;
        severity: string;
        cwe?: string;
      }>;
    }>;
  }>;
  summary: {
    totalFindings: number;
    findingsWithCwe: number;
    findingsWithMapping: number;
    frameworksCovered: number;
  };
}

export default function ComplianceFrameworkSelector({ scanSource, engagementId, domainId, className }: Props) {
  const [selectedFrameworks, setSelectedFrameworks] = useState<string[]>([]);
  const [report, setReport] = useState<ComplianceReportData | null>(null);
  const [expandedFramework, setExpandedFramework] = useState<string | null>(null);
  const [expandedControl, setExpandedControl] = useState<string | null>(null);

  const vulnScanMutation = trpc.complianceMapper.mapVulnScanToFrameworks.useMutation({
    onSuccess: (data) => {
      setReport(data as any);
      toast.success(`Mapped findings to ${selectedFrameworks.length} framework(s)`);
    },
    onError: (err) => toast.error(`Mapping failed: ${err.message}`),
  });

  const diScanMutation = trpc.complianceMapper.mapDiScanToFrameworks.useMutation({
    onSuccess: (data) => {
      setReport(data as any);
      toast.success(`Mapped DI findings to ${selectedFrameworks.length} framework(s)`);
    },
    onError: (err) => toast.error(`Mapping failed: ${err.message}`),
  });

  const isLoading = vulnScanMutation.isPending || diScanMutation.isPending;

  const toggleFramework = (fwId: string) => {
    setSelectedFrameworks(prev =>
      prev.includes(fwId) ? prev.filter(f => f !== fwId) : [...prev, fwId]
    );
    setReport(null); // Clear previous report when selection changes
  };

  const selectAll = () => {
    setSelectedFrameworks(Object.keys(FRAMEWORK_INFO));
    setReport(null);
  };

  const clearAll = () => {
    setSelectedFrameworks([]);
    setReport(null);
  };

  const runMapping = () => {
    if (selectedFrameworks.length === 0) {
      toast.error("Select at least one framework");
      return;
    }
    const fws = selectedFrameworks as any;
    if (scanSource === "engagement" && engagementId) {
      vulnScanMutation.mutate({ engagementId, frameworks: fws });
    } else if (scanSource === "di_scan" && domainId) {
      diScanMutation.mutate({ domainId, frameworks: fws });
    }
  };

  return (
    <div className={className}>
      {/* Framework Selection */}
      <Card className="border-border/50 bg-card/50">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-lg flex items-center gap-2">
                <Shield className="h-5 w-5 text-purple-400" />
                Compliance Framework Mapping
              </CardTitle>
              <CardDescription className="mt-1">
                Select frameworks to map {scanSource === "engagement" ? "vulnerability scan" : "domain intelligence"} findings against
              </CardDescription>
            </div>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" onClick={selectAll} className="text-xs">
                Select All
              </Button>
              <Button variant="outline" size="sm" onClick={clearAll} className="text-xs">
                Clear
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {Object.entries(FRAMEWORK_INFO).map(([fwId, fw]) => {
              const isSelected = selectedFrameworks.includes(fwId);
              return (
                <button
                  key={fwId}
                  onClick={() => toggleFramework(fwId)}
                  className={`flex items-start gap-3 p-3 rounded-lg border transition-all text-left ${
                    isSelected
                      ? `${fw.color} border-current/40 ring-1 ring-current/20`
                      : "border-border/30 bg-muted/20 hover:bg-muted/40 text-muted-foreground"
                  }`}
                >
                  <div className="flex items-center gap-2 mt-0.5">
                    <Checkbox checked={isSelected} className="pointer-events-none" />
                    <span className="text-lg">{fw.icon}</span>
                  </div>
                  <div className="min-w-0">
                    <div className="font-medium text-sm">{fw.label}</div>
                    <div className="text-xs opacity-70 mt-0.5">{fw.description}</div>
                  </div>
                </button>
              );
            })}
          </div>

          <div className="mt-4 flex items-center justify-between">
            <span className="text-sm text-muted-foreground">
              {selectedFrameworks.length} framework{selectedFrameworks.length !== 1 ? "s" : ""} selected
            </span>
            <Button
              onClick={runMapping}
              disabled={selectedFrameworks.length === 0 || isLoading}
              className="gap-2"
            >
              {isLoading ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Mapping...
                </>
              ) : (
                <>
                  <BarChart3 className="h-4 w-4" />
                  Generate Compliance Report
                </>
              )}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Report Results */}
      {report && (
        <div className="mt-4 space-y-4">
          {/* Summary Card */}
          <Card className="border-border/50 bg-card/50">
            <CardHeader className="pb-3">
              <CardTitle className="text-lg flex items-center gap-2">
                <FileText className="h-5 w-5 text-green-400" />
                Compliance Mapping Report
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="text-center p-3 rounded-lg bg-muted/20">
                  <div className="text-2xl font-bold text-foreground">{report.summary.totalFindings}</div>
                  <div className="text-xs text-muted-foreground mt-1">Total Findings</div>
                </div>
                <div className="text-center p-3 rounded-lg bg-muted/20">
                  <div className="text-2xl font-bold text-purple-400">{report.summary.findingsWithCwe}</div>
                  <div className="text-xs text-muted-foreground mt-1">CWE Identified</div>
                </div>
                <div className="text-center p-3 rounded-lg bg-muted/20">
                  <div className="text-2xl font-bold text-green-400">{report.summary.findingsWithMapping}</div>
                  <div className="text-xs text-muted-foreground mt-1">Mapped to Controls</div>
                </div>
                <div className="text-center p-3 rounded-lg bg-muted/20">
                  <div className="text-2xl font-bold text-blue-400">{report.summary.frameworksCovered}</div>
                  <div className="text-xs text-muted-foreground mt-1">Frameworks Covered</div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Per-Framework Results */}
          {report.frameworks.map((fw) => {
            const fwInfo = FRAMEWORK_INFO[fw.frameworkId];
            const isExpanded = expandedFramework === fw.frameworkId;
            const total = fw.totalControlsMapped;
            const failCount = fw.controlsByStatus?.fail || 0;
            const passCount = fw.controlsByStatus?.pass || 0;
            const partialCount = fw.controlsByStatus?.partial || 0;
            const complianceRate = total > 0 ? Math.round(((passCount + partialCount * 0.5) / total) * 100) : 0;

            return (
              <Card key={fw.frameworkId} className="border-border/50 bg-card/50">
                <button
                  onClick={() => setExpandedFramework(isExpanded ? null : fw.frameworkId)}
                  className="w-full text-left"
                >
                  <CardHeader className="pb-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <span className="text-xl">{fwInfo?.icon || "📋"}</span>
                        <div>
                          <CardTitle className="text-base">{fw.frameworkName}</CardTitle>
                          <CardDescription className="mt-0.5">
                            {total} controls mapped &middot; {failCount} gaps &middot; {passCount} covered
                          </CardDescription>
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        <div className="text-right">
                          <div className="text-sm font-medium">{complianceRate}%</div>
                          <Progress value={complianceRate} className="w-24 h-1.5 mt-1" />
                        </div>
                        {isExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                      </div>
                    </div>
                  </CardHeader>
                </button>

                {isExpanded && (
                  <CardContent className="pt-0">
                    <div className="space-y-2 max-h-96 overflow-y-auto">
                      {(fw.controls || []).map((ctrl) => {
                        const isCtrlExpanded = expandedControl === `${fw.frameworkId}-${ctrl.controlId}`;
                        return (
                          <div key={ctrl.controlId} className="border border-border/30 rounded-lg">
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                setExpandedControl(isCtrlExpanded ? null : `${fw.frameworkId}-${ctrl.controlId}`);
                              }}
                              className="w-full text-left p-3 flex items-center justify-between hover:bg-muted/20 rounded-lg"
                            >
                              <div className="flex items-center gap-2 min-w-0">
                                {ctrl.status === "fail" ? (
                                  <XCircle className="h-4 w-4 text-red-400 shrink-0" />
                                ) : ctrl.status === "pass" ? (
                                  <CheckCircle2 className="h-4 w-4 text-green-400 shrink-0" />
                                ) : (
                                  <AlertTriangle className="h-4 w-4 text-yellow-400 shrink-0" />
                                )}
                                <Badge variant="outline" className="text-xs shrink-0">{ctrl.controlId}</Badge>
                                <span className="text-sm truncate">{ctrl.controlTitle}</span>
                              </div>
                              <div className="flex items-center gap-2 shrink-0">
                                <Badge className={`text-xs ${
                                  ctrl.status === "fail" ? "bg-red-500/20 text-red-400" :
                                  ctrl.status === "pass" ? "bg-green-500/20 text-green-400" :
                                  "bg-yellow-500/20 text-yellow-400"
                                }`}>
                                  {ctrl.findings?.length || 0} finding{(ctrl.findings?.length || 0) !== 1 ? "s" : ""}
                                </Badge>
                              </div>
                            </button>
                            {isCtrlExpanded && ctrl.findings && ctrl.findings.length > 0 && (
                              <div className="px-3 pb-3 space-y-1.5 border-t border-border/20 pt-2">
                                {ctrl.findings.map((f, idx) => (
                                  <div key={idx} className="flex items-center gap-2 text-xs p-2 rounded bg-muted/20">
                                    <Badge className={`text-[10px] ${SEVERITY_COLORS[f.severity] || SEVERITY_COLORS.info}`}>
                                      {f.severity}
                                    </Badge>
                                    <span className="truncate flex-1">{f.title}</span>
                                    {f.cwe && (
                                      <Badge variant="outline" className="text-[10px] shrink-0">{f.cwe}</Badge>
                                    )}
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </CardContent>
                )}
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
