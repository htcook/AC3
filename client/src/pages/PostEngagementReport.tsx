import { sanitizeErrorForToast } from "@/lib/error-sanitizer";
import { useState, useMemo, useRef } from "react";
import { trpc } from "@/lib/trpc";
import AppShell from "@/components/AppShell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { toast } from "sonner";
import {
  FileText,
  Download,
  Loader2,
  Sparkles,
  Eye,
  Printer,
  CheckCircle2,
  Shield,
  Target,
  BarChart3,
  AlertTriangle,
} from "lucide-react";

const ENGAGEMENT_TYPES = [
  { value: "Purple Team Exercise", label: "Purple Team Exercise" },
  { value: "Red Team Assessment", label: "Red Team Assessment" },
  { value: "Adversary Emulation", label: "Adversary Emulation" },
  { value: "Detection Validation", label: "Detection Validation" },
  { value: "Penetration Test", label: "Penetration Test" },
  { value: "Tabletop Exercise", label: "Tabletop Exercise" },
];

export default function PostEngagementReport() {
  const [selectedOp, setSelectedOp] = useState<string>("");
  const [clientName, setClientName] = useState("");
  const [engagementType, setEngagementType] = useState("Purple Team Exercise");
  const [customNotes, setCustomNotes] = useState("");
  const [reportHtml, setReportHtml] = useState<string | null>(null);
  const [reportData, setReportData] = useState<any>(null);
  const iframeRef = useRef<HTMLIFrameElement>(null);

  const { data: operations, isLoading: opsLoading } = trpc.calderaProxy.getOperations.useQuery();

  const generateMutation = trpc.calderaProxy.generateReport.useMutation({
    onSuccess: (data) => {
      setReportHtml(data.html);
      setReportData(data.report);
      toast.success("Report generated successfully!");
    },
    onError: (err) => toast.error(`Report generation failed: ${sanitizeErrorForToast(err)}`),
  });

  const selectedOperation = useMemo(() => {
    if (!selectedOp || !operations) return null;
    return operations.find((o: any) => o.id === selectedOp);
  }, [selectedOp, operations]);

  const handleGenerate = () => {
    if (!selectedOp) {
      toast.error("Select an operation first");
      return;
    }
    generateMutation.mutate({
      operationId: selectedOp,
      clientName: clientName || undefined,
      engagementType,
      customNotes: customNotes || undefined,
    });
  };

  const handleDownload = () => {
    if (!reportHtml) return;
    const blob = new Blob([reportHtml], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${reportData?.metadata?.operationName || "report"}_post_engagement_report.html`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success("Report downloaded");
  };

  const handlePrint = () => {
    if (!iframeRef.current) return;
    iframeRef.current.contentWindow?.print();
  };

  return (
    <AppShell>
      <div className="p-6 space-y-6">
        {/* Header */}
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-2">
              <FileText className="w-6 h-6 text-cyan-400" />
              Post-Engagement Report Generator
            </h1>
            <p className="text-sm text-muted-foreground mt-1">
              Generate client-ready PDF reports from completed adversary operations with MITRE ATT&CK mapping,
              detection coverage analysis, and LLM-powered executive summaries.
            </p>
          </div>
        </div>

        {!reportHtml ? (
          <>
            {/* Operation Selection */}
            <Card className="bg-card/50">
              <CardHeader>
                <CardTitle className="text-sm flex items-center gap-2">
                  <Target className="w-4 h-4 text-cyan-400" />
                  Select Operation
                </CardTitle>
              </CardHeader>
              <CardContent>
                {opsLoading ? (
                  <div className="flex items-center gap-2 text-muted-foreground">
                    <Loader2 className="w-4 h-4 animate-spin" /> Loading operations...
                  </div>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                    {operations?.map((op: any) => (
                      <button
                        key={op.id}
                        onClick={() => setSelectedOp(op.id)}
                        className={`text-left p-3 rounded-lg border transition-all ${
                          selectedOp === op.id
                            ? "border-primary bg-primary/10"
                            : "border-border hover:border-primary/50 bg-muted/20"
                        }`}
                      >
                        <div className="font-medium text-sm truncate">{op.name}</div>
                        <div className="flex items-center gap-2 mt-1">
                          <Badge
                            variant="outline"
                            className={`text-xs ${
                              op.state === "running"
                                ? "border-green-500/30 text-green-400"
                                : op.state === "paused"
                                ? "border-yellow-500/30 text-yellow-400"
                                : "border-blue-500/30 text-blue-400"
                            }`}
                          >
                            {op.state}
                          </Badge>
                          <span className="text-xs text-muted-foreground">
                            {op.chain?.length || 0} steps
                          </span>
                        </div>
                        {op.adversary && (
                          <div className="text-xs text-muted-foreground mt-1 truncate">
                            Adversary: {op.adversary.name}
                          </div>
                        )}
                      </button>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Report Configuration */}
            <Card className="bg-card/50">
              <CardHeader>
                <CardTitle className="text-sm flex items-center gap-2">
                  <Shield className="w-4 h-4 text-cyan-400" />
                  Report Configuration
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="text-xs font-medium text-muted-foreground mb-1 block">
                      Client Name
                    </label>
                    <Input
                      value={clientName}
                      onChange={(e) => setClientName(e.target.value)}
                      placeholder="Enter client organization name"
                    />
                  </div>
                  <div>
                    <label className="text-xs font-medium text-muted-foreground mb-1 block">
                      Engagement Type
                    </label>
                    <Select value={engagementType} onValueChange={setEngagementType}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {ENGAGEMENT_TYPES.map((t) => (
                          <SelectItem key={t.value} value={t.value}>
                            {t.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <div>
                  <label className="text-xs font-medium text-muted-foreground mb-1 block">
                    Additional Notes (optional)
                  </label>
                  <Textarea
                    value={customNotes}
                    onChange={(e) => setCustomNotes(e.target.value)}
                    placeholder="Add any custom notes, scope details, or special observations to include in the report..."
                    rows={3}
                  />
                </div>
              </CardContent>
            </Card>

            {/* Selected Operation Summary */}
            {selectedOperation && (
              <Card className="bg-card/50 border-primary/30">
                <CardContent className="p-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="text-sm font-medium">{selectedOperation.name}</div>
                      <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
                        <span>State: {selectedOperation.state}</span>
                        <span>Steps: {selectedOperation.chain?.length || 0}</span>
                        {selectedOperation.adversary && (
                          <span>Adversary: {selectedOperation.adversary.name}</span>
                        )}
                      </div>
                    </div>
                    <Button
                      onClick={handleGenerate}
                      disabled={generateMutation.isPending}
                      className="bg-cyan-600 hover:bg-cyan-700"
                    >
                      {generateMutation.isPending ? (
                        <>
                          <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                          Generating...
                        </>
                      ) : (
                        <>
                          <Sparkles className="w-4 h-4 mr-2" />
                          Generate Report
                        </>
                      )}
                    </Button>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* What's Included */}
            <Card className="bg-card/50">
              <CardHeader>
                <CardTitle className="text-sm flex items-center gap-2">
                  <BarChart3 className="w-4 h-4 text-cyan-400" />
                  Report Contents
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  {[
                    {
                      title: "Executive Summary",
                      desc: "LLM-generated overview of engagement findings, risk posture, and key takeaways for stakeholders",
                      icon: <FileText className="w-5 h-5 text-blue-400" />,
                    },
                    {
                      title: "Attack Chain Analysis",
                      desc: "Technique-by-technique results with MITRE ATT&CK mapping, success/failure rates, and detection status",
                      icon: <Target className="w-5 h-5 text-red-400" />,
                    },
                    {
                      title: "Detection Coverage",
                      desc: "Cross-referenced rules vs. operation results showing SIEM coverage gaps with remediation recommendations",
                      icon: <Shield className="w-5 h-5 text-green-400" />,
                    },
                    {
                      title: "MITRE ATT&CK Heatmap",
                      desc: "Visual mapping of all tested techniques across tactical phases with color-coded results",
                      icon: <BarChart3 className="w-5 h-5 text-purple-400" />,
                    },
                    {
                      title: "Findings & Severity",
                      desc: "Prioritized list of undetected techniques with severity ratings and specific remediation steps",
                      icon: <AlertTriangle className="w-5 h-5 text-orange-400" />,
                    },
                    {
                      title: "Recommendations",
                      desc: "Actionable next steps generated by AI based on engagement results and industry best practices",
                      icon: <Sparkles className="w-5 h-5 text-amber-400" />,
                    },
                  ].map((item, i) => (
                    <div key={i} className="p-3 bg-muted/20 rounded-lg">
                      <div className="flex items-center gap-2 mb-2">
                        {item.icon}
                        <span className="text-sm font-medium">{item.title}</span>
                      </div>
                      <p className="text-xs text-muted-foreground">{item.desc}</p>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </>
        ) : (
          <>
            {/* Report Preview */}
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-5 h-5 text-green-400" />
                <span className="font-medium">Report Generated Successfully</span>
              </div>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" onClick={() => { setReportHtml(null); setReportData(null); }}>
                  <Target className="w-4 h-4 mr-1" /> New Report
                </Button>
                <Button variant="outline" size="sm" onClick={handlePrint}>
                  <Printer className="w-4 h-4 mr-1" /> Print
                </Button>
                <Button size="sm" className="bg-cyan-600 hover:bg-cyan-700" onClick={handleDownload}>
                  <Download className="w-4 h-4 mr-1" /> Download HTML
                </Button>
              </div>
            </div>

            {/* Report Summary Stats */}
            {reportData && (
              <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                <Card className="bg-card/50">
                  <CardContent className="p-3 text-center">
                    <div className="text-2xl font-bold text-blue-400">
                      {reportData.metrics?.totalSteps || 0}
                    </div>
                    <div className="text-xs text-muted-foreground">Total Steps</div>
                  </CardContent>
                </Card>
                <Card className="bg-card/50">
                  <CardContent className="p-3 text-center">
                    <div className="text-2xl font-bold text-green-400">
                      {reportData.metrics?.successRate || 0}%
                    </div>
                    <div className="text-xs text-muted-foreground">Success Rate</div>
                  </CardContent>
                </Card>
                <Card className="bg-card/50">
                  <CardContent className="p-3 text-center">
                    <div className="text-2xl font-bold text-red-400">
                      {reportData.metrics?.detectionRate || 0}%
                    </div>
                    <div className="text-xs text-muted-foreground">Detection Rate</div>
                  </CardContent>
                </Card>
                <Card className="bg-card/50">
                  <CardContent className="p-3 text-center">
                    <div className="text-2xl font-bold text-orange-400">
                      {reportData.findings?.length || 0}
                    </div>
                    <div className="text-xs text-muted-foreground">Findings</div>
                  </CardContent>
                </Card>
                <Card className="bg-card/50">
                  <CardContent className="p-3 text-center">
                    <div className="text-2xl font-bold text-cyan-400">
                      {reportData.detectionCoverage?.coveragePercentage || 0}%
                    </div>
                    <div className="text-xs text-muted-foreground">Coverage</div>
                  </CardContent>
                </Card>
              </div>
            )}

            {/* HTML Preview */}
            <Card className="bg-card/50">
              <CardContent className="p-0">
                <iframe
                  ref={iframeRef}
                  srcDoc={reportHtml}
                  className="w-full border-0 rounded-lg"
                  style={{ height: "80vh" }}
                  title="Report Preview"
                  sandbox="allow-same-origin allow-popups"
                />
              </CardContent>
            </Card>
          </>
        )}
      </div>
    </AppShell>
  );
}
